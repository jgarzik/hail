
/*
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define _GNU_SOURCE

#include "cld-config.h"

#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <openssl/sha.h>
#include "cld.h"

struct session_outpkt;

struct session_outpkt {
	struct session		*sess;

	struct cld_packet	*pkt;
	size_t			pkt_len;

	uint64_t		next_retry;
	uint64_t		src_seqid;
	unsigned int		refs;

	void			(*done_cb)(struct session_outpkt *);
	void			*done_data;
};

static void session_retry(struct timer *);
static void session_timeout(struct timer *);
static int sess_load_db(GHashTable *ss, DB_TXN *txn);

uint64_t next_seqid_le(uint64_t *seq)
{
	uint64_t tmp, rc;

	tmp = *seq;
	rc = GUINT64_TO_LE(tmp);
	*seq = tmp + 1;

	return rc;
}

void pkt_init_pkt(struct cld_packet *dest, const struct cld_packet *src)
{
	memset(dest, 0, sizeof(*dest));
	memcpy(dest->magic, CLD_PKT_MAGIC, CLD_MAGIC_SZ);
	dest->seqid = GUINT64_TO_LE(0xdeadbeef);
	memcpy(dest->sid, src->sid, CLD_SID_SZ);
	dest->n_msg = 1;
	strncpy(dest->user, src->user, CLD_MAX_USERNAME - 1);
}

void pkt_init_sess(struct cld_packet *dest, struct session *sess)
{
	memset(dest, 0, sizeof(*dest));
	memcpy(dest->magic, CLD_PKT_MAGIC, CLD_MAGIC_SZ);
	dest->seqid = next_seqid_le(&sess->next_seqid_out);
	memcpy(dest->sid, sess->sid, CLD_SID_SZ);
	dest->n_msg = 1;
	strncpy(dest->user, sess->user, CLD_MAX_USERNAME - 1);
}

guint sess_hash(gconstpointer v)
{
	const struct session *sess = v;
	const uint64_t *tmp = (const uint64_t *) sess->sid;

	return (guint) *tmp;
}

gboolean sess_equal(gconstpointer _a, gconstpointer _b)
{
	const struct session *a = _a;
	const struct session *b = _b;

	return (memcmp(a->sid, b->sid, CLD_SID_SZ) == 0);
}

static struct session *session_new(void)
{
	struct session *sess;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return NULL;

	sess->next_fh = 2;

	__cld_rand64(&sess->next_seqid_out);

	timer_init(&sess->timer, session_timeout, sess);
	timer_init(&sess->retry_timer, session_retry, sess);

	return sess;
}

static void session_free(struct session *sess)
{
	if (!sess)
		return;

	g_hash_table_remove(cld_srv.sessions, sess->sid);

	timer_del(&sess->timer);
	timer_del(&sess->retry_timer);

	free(sess);
}

static bool lmatch(const struct raw_lock *lock, uint8_t *sid, uint64_t fh)
{
	if (memcmp(lock->sid, sid, sizeof(lock->sid)))
		return false;
	if (fh && (GUINT64_FROM_LE(lock->fh) != fh))
		return false;

	return true;
}

int session_remove_locks(DB_TXN *txn, uint8_t *sid, uint64_t fh,
			 cldino_t inum, bool *waiter)
{
	DB *db_locks = cld_srv.cldb.locks;
	DBC *cur;
	*waiter = false;
	int rc;
	DBT pkey, pval;
	cldino_t inum_le = cldino_to_le(inum);
	int gflags;
	struct raw_lock l;

	*waiter = false;

	rc = db_locks->cursor(db_locks, txn, &cur, 0);
	if (rc) {
		db_locks->err(db_locks, rc, "session_remove_locks cur");
		goto err_out;
	}

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = &inum_le;
	pkey.size = sizeof(inum_le);

	pval.data = &l;
	pval.ulen = sizeof(l);
	pval.flags = DB_DBT_USERMEM;

	gflags = DB_SET;
	while (1) {
		/* search for first/next matching lock */
		rc = cur->get(cur, &pkey, &pval, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				db_locks->err(db_locks, rc, "curget2");
			break;
		}

		gflags = DB_NEXT_DUP;

		/* if not our sid, check for pending lock acquisitions */
		if (!lmatch(&l, sid, fh)) {
			if (GUINT32_FROM_LE(l.flags) & CLFL_PENDING)
				*waiter = true;
		}

		/* delete lock matching search criteria */
		else {
			rc = cur->del(cur, 0);
			if (rc) {
				db_locks->err(db_locks, rc, "curdel2");
				break;
			}
		}
	}

	/* close cursor, being careful to preserve return value
	 * in most cases, but ignoring it in some others
	 */
	if (rc == DB_NOTFOUND)
		rc = 0;
	if (rc)
		cur->close(cur);
	else {
		rc = cur->close(cur);
		if (rc)
			db_locks->err(db_locks, rc, "curclose2");
	}
	if (rc)
		goto err_out;

	return 0;

err_out:
	return rc;
}

static int session_remove(DB_TXN *txn, struct session *sess)
{
	DB *db_handles = cld_srv.cldb.handles;
	DBC *cur;
	struct raw_handle_key hkey;
	struct raw_handle h;
	int rc, i;
	DBT pkey, pval;
	GArray *locks, *waiters;
	int gflags;

	memcpy(hkey.sid, sess->sid, sizeof(sess->sid));
	hkey.fh = 0;

	locks = g_array_sized_new(FALSE, TRUE, sizeof(cldino_t), 128);
	if (!locks)
		return -ENOMEM;
	waiters = g_array_sized_new(FALSE, TRUE, sizeof(cldino_t), 64);
	if (!waiters) {
		rc = -ENOMEM;
		goto err_out;
	}

	rc = db_handles->cursor(db_handles, txn, &cur, 0);
	if (rc) {
		db_handles->err(db_handles, rc, "session_remove cur1");
		goto err_out;
	}

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = &hkey;
	pkey.size = sizeof(hkey);

	pval.data = &h;
	pval.ulen = sizeof(h);
	pval.flags = DB_DBT_USERMEM;

	/* loop through handles, deleting those with our sid */
	gflags = DB_SET_RANGE;
	while (1) {
		/* search for first/next matching handle */
		rc = cur->get(cur, &pkey, &pval, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				db_handles->err(db_handles, rc, "curget1");
			break;
		}

		gflags = DB_NEXT;

		/* verify same sid */
		if (memcmp(h.sid, sess->sid, CLD_SID_SZ))
			break;

		if (GUINT32_FROM_LE(h.mode) & COM_LOCK) {
			cldino_t inum;

			inum = cldino_from_le(h.inum);
			g_array_append_val(locks, inum);
		}

		rc = cur->del(cur, 0);
		if (rc) {
			db_handles->err(db_handles, rc, "curdel1");
			break;
		}
	}

	/* close cursor, being careful to preserve return value
	 * in most cases, but ignoring it in some others
	 */
	if (rc == DB_NOTFOUND)
		rc = 0;
	if (rc)
		cur->close(cur);
	else {
		rc = cur->close(cur);
		if (rc)
			db_handles->err(db_handles, rc, "curclose1");
	}
	if (rc)
		goto err_out;

	/*
	 * scan locks for waiters; delete our locks
	 */
	for (i = 0; i < locks->len; i++) {
		cldino_t inum;
		bool waiter;

		inum = g_array_index(locks, cldino_t, i);
		rc = session_remove_locks(txn, sess->sid, 0, inum, &waiter);
		if (rc)
			goto err_out;

		if (waiter)
			g_array_append_val(waiters, inum);
	}

	/* rescan each inode in 'waiters', possibly acquiring locks */
	for (i = 0; i < waiters->len; i++) {
		rc = inode_lock_rescan(txn,
				       g_array_index(waiters, cldino_t, i));
		if (rc)
			goto err_out;
	}

	/*
	 * finally, delete the session
	 */
	rc = cldb_session_del(txn, sess->sid);
	if (rc)
		goto err_out;

	g_array_free(locks, TRUE);
	g_array_free(waiters, TRUE);
	return 0;

err_out:
	g_array_free(locks, TRUE);
	g_array_free(waiters, TRUE);
	return rc;
}

int session_dispose(DB_TXN *txn, struct session *sess)
{
	int rc;

	if (!sess)
		return -EINVAL;

	rc = session_remove(txn, sess);

	session_free(sess);

	if (rc)
		cldlog(LOG_WARNING, "failed to remove session\n");

	return rc;
}

static void session_ping_done(struct session_outpkt *outpkt)
{
	outpkt->sess->ping_open = false;
}

static void session_ping(struct session *sess)
{
	struct cld_msg_hdr resp;

	memset(&resp, 0, sizeof(resp));
	resp.op = cmo_ping;

	sess->ping_open = true;

	sess_sendmsg(sess, &resp, sizeof(resp), session_ping_done, NULL);
}

static void session_timeout(struct timer *timer)
{
	struct session *sess = timer->userdata;
	uint64_t sess_expire;
	int rc;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	time_t now = time(NULL);

	sess_expire = sess->last_contact + CLD_SESS_TIMEOUT;
	if (sess_expire > now) {
		if (!sess->ping_open &&
		    (sess_expire > (sess->last_contact + (CLD_SESS_TIMEOUT / 2) &&
		    sess->sock)))
			session_ping(sess);

		timer_add(&sess->timer, now + ((sess_expire - now) / 2) + 1);
		return;	/* timer added; do not time out session */
	}

	cldlog(LOG_INFO, "session timeout, addr %s sid " SIDFMT "\n",
		sess->ipaddr, SIDARG(sess->sid));

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return;
	}

	/* dispose of session */
	rc = session_dispose(txn, sess);

	/* close transaction */
	if (rc) {
		rc = txn->abort(txn);
		if (rc)
			dbenv->err(dbenv, rc, "session txn_abort");
	} else {
		rc = txn->commit(txn, 0);
		if (rc)
			dbenv->err(dbenv, rc, "session txn_commit");
	}
}

static void session_encode(struct raw_session *raw, const struct session *sess)
{
	memcpy(raw, sess, CLD_SID_SZ);

	raw->addr_len = GUINT16_TO_LE(sess->addr_len);
	memcpy(&raw->addr, &sess->addr, sess->addr_len);

	memcpy(raw->user, sess->user, CLD_MAX_USERNAME);

	raw->last_contact = GUINT64_TO_LE(sess->last_contact);
	raw->next_fh = GUINT64_TO_LE(sess->next_fh);
	raw->next_seqid_in = GUINT64_TO_LE(sess->next_seqid_in);
	raw->next_seqid_out = GUINT64_TO_LE(sess->next_seqid_out);
}

static void session_decode(struct session *sess, const struct raw_session *raw)
{
	/*
	 * The sess->sock is going to get filled on first message from client.
	 */

	memcpy(sess->sid, raw->sid, sizeof(sess->sid));

	sess->addr_len = GUINT16_FROM_LE(raw->addr_len);
	memcpy(&sess->addr, &raw->addr, sess->addr_len);

	getnameinfo((struct sockaddr *) &sess->addr, sess->addr_len,
		    sess->ipaddr, CLD_IPADDR_SZ, NULL, 0, NI_NUMERICHOST);
	sess->ipaddr[CLD_IPADDR_SZ - 1] = 0;

	sess->last_contact = GUINT64_FROM_LE(raw->last_contact);
	sess->next_fh = GUINT64_FROM_LE(raw->next_fh);

	sess->next_seqid_out = GUINT64_FROM_LE(raw->next_seqid_out);
	sess->next_seqid_in = GUINT64_FROM_LE(raw->next_seqid_in);

	memcpy(sess->user, raw->user, CLD_MAX_USERNAME);
}

struct raw_session *session_new_raw(const struct session *sess)
{
	struct raw_session *raw_sess;

	raw_sess = malloc(sizeof(*raw_sess));
	if (!raw_sess)
		return NULL;

	session_encode(raw_sess, sess);

	return raw_sess;
}

static struct session_outpkt *op_alloc(size_t pkt_len)
{
	struct session_outpkt *op;

	op = calloc(1, sizeof(*op));
	if (!op)
		return NULL;

	op->pkt = calloc(1, pkt_len);
	if (!op->pkt) {
		free(op);
		return NULL;
	}

	op->pkt_len = pkt_len;
	op->refs = 1;

	return op;
}

static void op_unref(struct session_outpkt *op)
{
	if (!op)
		return;

	if (op->refs) {
		op->refs--;
		if (op->refs)
			return;
	}

	free(op->pkt);
	free(op);
}

static int sess_retry_output(struct session *sess)
{
	GList *tmp, *tmp1;
	struct session_outpkt *op;
	int rc = 0;

	tmp = sess->out_q;
	while (tmp) {
		struct cld_packet *outpkt;
		struct cld_msg_hdr *outmsg;

		tmp1 = tmp;
		tmp = tmp->next;

		op = tmp1->data;
		outpkt = op->pkt;
		outmsg = (struct cld_msg_hdr *) (outpkt + 1);

		if (current_time.tv_sec < op->next_retry)
			continue;

		if (debugging)
			cldlog(LOG_DEBUG,
			       "retry: sid " SIDFMT ", op %s, seqid %llu\n",
			       SIDARG(outpkt->sid),
			       opstr(outmsg->op),
			       (unsigned long long)
					GUINT64_FROM_LE(outpkt->seqid));

		rc = udp_tx(sess->sock, (struct sockaddr *) &sess->addr,
			    sess->addr_len, op->pkt, op->pkt_len);
		if (rc)
			break;

		op->next_retry *= 2;
	}

	return rc;
}

static void session_retry(struct timer *timer)
{
	struct session *sess = timer->userdata;

	sess_retry_output(sess);

	timer_add(&sess->retry_timer, time(NULL) + CLD_RETRY_START);
}

bool sess_sendmsg(struct session *sess, const void *msg_, size_t msglen,
		  void (*done_cb)(struct session_outpkt *),
		  void *done_data)
{
	struct cld_packet *outpkt;
	struct cld_msg_hdr *msg;
	struct session_outpkt *op;
	size_t pkt_len;

	if (debugging) {
		const struct cld_msg_hdr *hdr = msg_;
		const struct cld_msg_resp *rsp;

		switch (hdr->op) {
		/* This is the command set that gets to cldc_rx_generic */
		case cmo_nop:
		case cmo_close:
		case cmo_del:
		case cmo_lock:
		case cmo_unlock:
		case cmo_trylock:
		case cmo_put:
		case cmo_new_sess:
		case cmo_end_sess:
		case cmo_open:
		case cmo_data_s:
		case cmo_get_meta:
		case cmo_get:
			rsp = (struct cld_msg_resp *) msg_;
			cldlog(LOG_DEBUG, "sendmsg: "
			       "sid " SIDFMT ", op %s, msglen %u, code %u\n",
			       SIDARG(sess->sid),
			       opstr(hdr->op),
			       (unsigned int) msglen,
			       GUINT32_FROM_LE(rsp->code));
			break;
		default:
			cldlog(LOG_DEBUG,
			       "sendmsg: sid " SIDFMT ", op %s, msglen %u\n",
			       SIDARG(sess->sid),
			       opstr(hdr->op),
			       (unsigned int) msglen);
		}
	}

	op = op_alloc(sizeof(*outpkt) + msglen + SHA_DIGEST_LENGTH);
	if (!op)
		return false;

	op->sess = sess;
	op->done_cb = done_cb;
	op->done_data = done_data;

	outpkt = op->pkt;
	pkt_len = op->pkt_len;

	msg = (struct cld_msg_hdr *) (outpkt + 1);

	/* init packet header */
	pkt_init_sess(outpkt, sess);

	/* init message header */
	memcpy(msg->magic, CLD_MSG_MAGIC, CLD_MAGIC_SZ);
	msg->op = ((struct cld_msg_hdr *)msg_)->op;

	/* copy message trailer */
	memcpy(msg + 1, msg_ + sizeof(*msg), msglen - sizeof(*msg));

	op->pkt = outpkt;
	op->pkt_len = pkt_len;
	op->next_retry = current_time.tv_sec + CLD_RETRY_START;

	if (!authsign(outpkt, pkt_len)) {
		op_unref(op);
		return false;
	}

	/* if out_q empty, start retry timer */
	if (!sess->out_q)
		timer_add(&sess->retry_timer, time(NULL) + CLD_RETRY_START);

	sess->out_q = g_list_append(sess->out_q, op);

	udp_tx(sess->sock, (struct sockaddr *) &sess->addr,
	       sess->addr_len, outpkt, pkt_len);

	return true;
}

void msg_ack(struct msg_params *mp)
{
	struct cld_packet *outpkt;
	struct cld_msg_hdr *outmsg;
	GList *tmp, *tmp1;
	struct session *sess = mp->sess;
	struct session_outpkt *op;

	if (!sess->out_q)
		return;

	/* look through output queue */
	tmp = sess->out_q;
	while (tmp) {
		tmp1 = tmp;
		tmp = tmp->next;

		op = tmp1->data;
		outpkt = op->pkt;
		outmsg = (struct cld_msg_hdr *) (outpkt + 1);

		/* if matching seqid found, we ack'd a message in out_q */
		if (mp->pkt->seqid != outpkt->seqid)
			continue;

		if (debugging)
			cldlog(LOG_DEBUG, "    expiring seqid %llu\n",
		           (unsigned long long) GUINT64_FROM_LE(outpkt->seqid));

		/* remove and delete the ack'd msg; call ack'd callback */
		sess->out_q = g_list_delete_link(sess->out_q, tmp1);

		if (op->done_cb)
			op->done_cb(op);
		op_unref(op);
	}

	if (!sess->out_q)
		timer_del(&sess->retry_timer);
}

void msg_new_sess(struct msg_params *mp, const struct client *cli)
{
	DB *db = cld_srv.cldb.sessions;
	struct raw_session raw_sess;
	struct session *sess = NULL;
	DBT key, val;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	struct cld_msg_resp *resp;
	struct cld_packet *outpkt;
	size_t alloc_len;

	sess = session_new();
	if (!sess) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	/* build raw_session database record */
	memcpy(sess->sid, mp->pkt->sid, sizeof(sess->sid));
	memcpy(&sess->addr, &cli->addr, sizeof(sess->addr));

	strncpy(sess->user, mp->pkt->user, sizeof(sess->user));
	sess->user[sizeof(sess->user) - 1] = 0;

	sess->sock = mp->sock;
	sess->addr_len = cli->addr_len;
	strncpy(sess->ipaddr, cli->addr_host, sizeof(sess->ipaddr));
	sess->last_contact = current_time.tv_sec;
	sess->next_seqid_in = GUINT64_FROM_LE(mp->pkt->seqid) + 1;

	session_encode(&raw_sess, sess);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: sid */
	key.data = raw_sess.sid;
	key.size = sizeof(raw_sess.sid);

	val.data = &raw_sess;
	val.size = sizeof(raw_sess);

	/* attempt to store session; if session already exists,
	 * this should fail
	 */
	rc = db->put(db, NULL, &key, &val, DB_NOOVERWRITE);
	if (rc) {
		if (rc == DB_KEYEXIST)
			resp_rc = CLE_SESS_EXISTS;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	g_hash_table_insert(cld_srv.sessions, sess->sid, sess);

	/* begin session timer */
	timer_add(&sess->timer, time(NULL) + (CLD_SESS_TIMEOUT / 2));

	resp_ok(sess, mp->msg);
	return;

err_out:
	session_free(sess);

	alloc_len = sizeof(*outpkt) + sizeof(*resp) + SHA_DIGEST_LENGTH;
	outpkt = alloca(alloc_len);
	memset(outpkt, 0, alloc_len);

	pkt_init_pkt(outpkt, mp->pkt);

	resp = (struct cld_msg_resp *) (outpkt + 1);
	resp_copy(resp, mp->msg);
	resp->code = GUINT32_TO_LE(resp_rc);

	authsign(outpkt, alloc_len);

	if (debugging)
		cldlog(LOG_DEBUG,
		       "new_sess err: sid " SIDFMT ", op %s, seqid %llu\n",
		       SIDARG(outpkt->sid),
		       opstr(resp->hdr.op),
		       (unsigned long long) GUINT64_FROM_LE(outpkt->seqid));

	udp_tx(mp->sock, (struct sockaddr *) &mp->cli->addr,
	       mp->cli->addr_len, outpkt, alloc_len);

	if (debugging)
		cldlog(LOG_DEBUG, "NEW-SESS failed: %d\n", resp_rc);
}

static void end_sess_done(struct session_outpkt *outpkt)
{
	struct session *sess = outpkt->sess;

	outpkt->sess = NULL;

	session_free(sess);
}

void msg_end_sess(struct msg_params *mp, const struct client *cli)
{
	int rc;
	struct session *sess = mp->sess;
	struct cld_msg_resp resp;
	enum cle_err_codes resp_rc = CLE_OK;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	rc = session_remove(txn, sess);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	memset(&resp, 0, sizeof(resp));
	resp_copy(&resp, mp->msg);
	sess_sendmsg(sess, &resp, sizeof(resp), end_sess_done, NULL);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(sess, mp->msg, resp_rc);
}

/*
 * Fill ss with contents of the database.
 * Returns -1 on error because it prints the diagnostic to the log.
 */
int sess_load(GHashTable *ss)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	int rc;

	/*
	 * We're not sure if transactions are actually necessary for r/o
	 * accesses, but let's do it for commonality. They don't seem to hurt.
	 */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return -1;
	}

	if (sess_load_db(ss, txn) != 0) {
		txn->abort(txn);
		return -1;
	}

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");

	return 0;
}

static int sess_load_db(GHashTable *ss, DB_TXN *txn)
{
	DB *db = cld_srv.cldb.sessions;
	DBC *cur;
	DBT key, val;
	struct session *sess;
	struct raw_session raw_sess;
	int rc;

	rc = db->cursor(db, txn, &cur, 0);
	if (rc) {
		db->err(db, rc, "sess_load cur");
		return -1;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	val.data = &raw_sess;
	val.ulen = sizeof(raw_sess);
	val.flags = DB_DBT_USERMEM;

	while (1) {
		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc == DB_NOTFOUND)
			break;
		if (rc) {
			db->err(db, rc, "sess_load get");
			cur->close(cur);
			return -1;
		}

		sess = session_new();
		if (!sess) {
			db->err(db, rc, "sess_load alloc");
			cur->close(cur);
			return -1;
		}

		session_decode(sess, &raw_sess);

		if (debugging)
			cldlog(LOG_DEBUG,
			       " loaded sid " SIDFMT " next seqid %llu/%llu",
			       SIDARG(sess->sid),
			       (unsigned long long)
					GUINT64_FROM_LE(sess->next_seqid_out),
			       (unsigned long long)
					GUINT64_FROM_LE(sess->next_seqid_in));

		g_hash_table_insert(ss, sess->sid, sess);

		/* begin session timer */
		timer_add(&sess->timer, time(NULL) + (CLD_SESS_TIMEOUT / 2));
	}

	cur->close(cur);
	return 0;
}


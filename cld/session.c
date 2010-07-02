
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
#include "hail-config.h"

#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <openssl/sha.h>
#include <cld-private.h>
#include "cld.h"

struct session_outpkt {
	struct session		*sess;

	char			*pkt_data;
	size_t			pkt_len;

	uint64_t		next_retry;
	unsigned int		refs;

	void			(*done_cb)(struct session_outpkt *);
	void			*done_data;
};

static void session_retry(struct cld_timer *);
static void session_timeout(struct cld_timer *);
static int sess_load_db(GHashTable *ss, DB_TXN *txn);
static void op_unref(struct session_outpkt *op);

uint64_t next_seqid_le(uint64_t *seq)
{
	uint64_t tmp, rc;

	tmp = *seq;
	rc = cpu_to_le64(tmp);
	*seq = tmp + 1;

	return rc;
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

	cld_timer_init(&sess->timer, "session-timeout", session_timeout, sess);
	cld_timer_init(&sess->retry_timer, "session-retry", session_retry, sess);

	return sess;
}

static void session_free(struct session *sess, bool hash_remove)
{
	GList *tmp;

	if (!sess)
		return;

	if (hash_remove)
		g_hash_table_remove(cld_srv.sessions, sess->sid);

	cld_timer_del(&cld_srv.timers, &sess->timer);
	cld_timer_del(&cld_srv.timers, &sess->retry_timer);

	tmp = sess->out_q;
	while (tmp) {
		struct session_outpkt *op;

		op = tmp->data;
		op_unref(op);

		tmp->data = NULL;
		tmp = tmp->next;
	}

	g_list_free(sess->out_q);

	free(sess);
}

static void session_free_iter(gpointer key, gpointer val, gpointer dummy)
{
	session_free(val, false);
}

void sessions_free(void)
{
	g_hash_table_foreach(cld_srv.sessions, session_free_iter, NULL);
}

static void session_trash(struct session *sess)
{
	HAIL_DEBUG(&srv_log, "session " SIDFMT " sent to garbage",
		   SIDARG(sess->sid));
	sess->dead = true;
}

static bool lmatch(const struct raw_lock *lock, uint8_t *sid, uint64_t fh)
{
	if (memcmp(lock->sid, sid, sizeof(lock->sid)))
		return false;
	if (fh && (le64_to_cpu(lock->fh) != fh))
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
			if (le32_to_cpu(l.flags) & CLFL_PENDING)
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

		if (le32_to_cpu(h.mode) & COM_LOCK) {
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

	session_free(sess, true);

	if (rc)
		HAIL_WARN(&srv_log, "failed to remove session");

	return rc;
}

static void session_ping_done(struct session_outpkt *outpkt)
{
	outpkt->sess->ping_open = false;
}

static void session_timeout(struct cld_timer *timer)
{
	struct session *sess = timer->userdata;
	uint64_t sess_expire;
	int rc;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	time_t now = time(NULL);

	sess_expire = sess->last_contact + CLD_SESS_TIMEOUT;
	if (!sess->dead && (sess_expire > now)) {
		if (!sess->ping_open &&
		    (sess_expire > (sess->last_contact + (CLD_SESS_TIMEOUT / 2) &&
		    (sess->sock_fd > 0)))) {
			sess->ping_open = true;
			sess_sendmsg(sess,
				     (xdrproc_t)xdr_void, NULL, CMO_PING,
				     session_ping_done, NULL);
		}

		cld_timer_add(&cld_srv.timers, &sess->timer,
			      now + ((sess_expire - now) / 2) + 1);
		return;	/* timer added; do not time out session */
	}

	HAIL_INFO(&srv_log, "session %s, addr %s sid " SIDFMT,
		  sess->dead ? "gc'd" : "timeout",
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
	memset(raw, 0, sizeof(*raw));
	memcpy(raw, sess, CLD_SID_SZ);

	raw->addr_len = cpu_to_le16(sess->addr_len);
	memcpy(&raw->addr, &sess->addr, sess->addr_len);

	memcpy(raw->user, sess->user, CLD_MAX_USERNAME);

	raw->last_contact = cpu_to_le64(sess->last_contact);
	raw->next_fh = cpu_to_le64(sess->next_fh);
	raw->next_seqid_in = cpu_to_le64(sess->next_seqid_in);
	raw->next_seqid_out = cpu_to_le64(sess->next_seqid_out);
}

static void session_decode(struct session *sess, const struct raw_session *raw)
{
	/*
	 * The sess->sock is going to get filled on first message from client.
	 */

	memcpy(sess->sid, raw->sid, sizeof(sess->sid));

	sess->addr_len = le16_to_cpu(raw->addr_len);
	memcpy(&sess->addr, &raw->addr, sess->addr_len);

	getnameinfo((struct sockaddr *) &sess->addr, sess->addr_len,
		    sess->ipaddr, CLD_IPADDR_SZ, NULL, 0, NI_NUMERICHOST);
	sess->ipaddr[CLD_IPADDR_SZ - 1] = 0;

	sess->last_contact = le64_to_cpu(raw->last_contact);
	sess->next_fh = le64_to_cpu(raw->next_fh);

	sess->next_seqid_out = le64_to_cpu(raw->next_seqid_out);
	sess->next_seqid_in = le64_to_cpu(raw->next_seqid_in);

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

	op->pkt_data = calloc(1, pkt_len);
	if (!op->pkt_data) {
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

	free(op->pkt_data);
	free(op);
}

static int sess_retry_output(struct session *sess, time_t *next_retry_out)
{
	GList *tmp;
	int rc = 0;
	time_t next_retry = 0;

	*next_retry_out = 0;

	tmp = sess->out_q;
	while (tmp) {
		struct session_outpkt *op;
		op = tmp->data;
		tmp = tmp->next;

		if (!next_retry || (op->next_retry < next_retry))
			*next_retry_out = next_retry = op->next_retry;

		if (current_time.tv_sec < op->next_retry)
			continue;

		if (srv_log.verbose) {
			char scratch[PKT_HDR_TO_STR_SCRATCH_LEN];
			HAIL_DEBUG(&srv_log, "%s: retrying %s",
				   __func__,
				   __cld_pkt_hdr_to_str(scratch, op->pkt_data,
				  			op->pkt_len));
		}

		rc = udp_tx(sess->sock_fd, (struct sockaddr *) &sess->addr,
			    sess->addr_len, op->pkt_data, op->pkt_len);
		if (rc)
			break;

		op->next_retry += 5;
	}

	return rc;
}

static void session_retry(struct cld_timer *timer)
{
	struct session *sess = timer->userdata;
	time_t next_retry;

	if (!sess->out_q)
		return;

	sess_retry_output(sess, &next_retry);

	cld_timer_add(&cld_srv.timers, &sess->retry_timer, next_retry);
}

static void session_outq(struct session *sess, GList *new_pkts)
{
	/* if out_q empty, start retry timer */
	if (!sess->out_q)
		cld_timer_add(&cld_srv.timers, &sess->retry_timer,
			      time(NULL) + CLD_RETRY_START);

	sess->out_q = g_list_concat(sess->out_q, new_pkts);
}

bool sess_sendmsg(struct session *sess,
	xdrproc_t xdrproc, const void *xdrdata, enum cld_msg_op msg_op,
	void (*done_cb)(struct session_outpkt *), void *done_data)
{
	XDR xmsg;
	size_t msg_rem, msg_len, msg_chunk_len;
	char *msg_bytes, *msg_cur;
	GList *tmp_list, *new_pkts = NULL;
	int first, last;
	const char *secret_key;

	secret_key = user_key(sess->user);

	/* Use XDR to serialize the message */
	msg_len = xdr_sizeof(xdrproc, (void *)xdrdata);
	if (msg_len > CLD_MAX_MSG_SZ)
		return false;
	msg_bytes = alloca(msg_len);
	xdrmem_create(&xmsg, msg_bytes, msg_len, XDR_ENCODE);
	if (!xdrproc(&xmsg, (void *)xdrdata)) {
		xdr_destroy(&xmsg);
		HAIL_ERR(&srv_log, "%s: xdrproc failed", __func__);
		return false;
	}
	xdr_destroy(&xmsg);

	/* Break the message into packets */
	first = 1;
	msg_rem = msg_len;
	msg_cur = msg_bytes;
	do {
		XDR xout;
		struct cld_pkt_hdr pkt;
		size_t hdr_len;
		struct session_outpkt *op;

		if (msg_rem <= CLD_MAX_PKT_MSG_SZ) {
			msg_chunk_len = msg_rem;
			last = 1;
		} else {
			msg_chunk_len = CLD_MAX_PKT_MSG_SZ;
			last = 0;
		}

		/* Set up packet header */
		memset(&pkt, 0, sizeof(pkt));
		memcpy(&pkt.magic, CLD_PKT_MAGIC, sizeof(pkt.magic));
		memcpy(&pkt.sid, sess->sid, CLD_SID_SZ);
		pkt.user = sess->user;
		if (first) {
			struct cld_pkt_msg_infos *infos =
				&pkt.mi.cld_pkt_msg_info_u.mi;
			if (last)
				pkt.mi.order = CLD_PKT_ORD_FIRST_LAST;
			else
				pkt.mi.order = CLD_PKT_ORD_FIRST;
			__cld_rand64(&infos->xid);
			infos->op = msg_op;
		} else {
			if (last)
				pkt.mi.order = CLD_PKT_ORD_LAST;
			else
				pkt.mi.order = CLD_PKT_ORD_MID;
		}

		/* Allocate space and initialize session_outpkt structure */
		hdr_len = xdr_sizeof((xdrproc_t)xdr_cld_pkt_hdr, (void *)&pkt);
		op = op_alloc(hdr_len + msg_chunk_len + CLD_PKT_FTR_LEN);
		if (!op) {
			HAIL_DEBUG(&srv_log, "%s: op_alloc failed",
				   __func__);
			goto err_out;
		}
		op->sess = sess;
		op->next_retry = current_time.tv_sec + CLD_RETRY_START;
		op->done_cb = done_cb;
		op->done_data = done_data;
		xdrmem_create(&xout, op->pkt_data, hdr_len, XDR_ENCODE);
		if (!xdr_cld_pkt_hdr(&xout, &pkt)) {
			xdr_destroy(&xout);
			HAIL_ERR(&srv_log, "%s: xdr_cld_pkt_hdr failed",
				  __func__);
			goto err_out;
		}
		xdr_destroy(&xout);

		/* Fill in data */
		memcpy(op->pkt_data + hdr_len, msg_cur, msg_chunk_len);
		msg_cur += msg_chunk_len;
		msg_rem -= msg_chunk_len;
		first = 0;

		new_pkts = g_list_prepend(new_pkts, op);
	} while (!last);

	/* add sequence IDs and SHAs */
	new_pkts = g_list_reverse(new_pkts);
	for (tmp_list = g_list_first(new_pkts);
	     tmp_list;
	     tmp_list = g_list_next(tmp_list)) {
		struct session_outpkt *op =
			(struct session_outpkt *) tmp_list->data;
		struct cld_pkt_ftr *foot = (struct cld_pkt_ftr *)
			(op->pkt_data + (op->pkt_len - CLD_PKT_FTR_LEN));
		int ret;

		foot->seqid = next_seqid_le(&sess->next_seqid_out);
		ret = __cld_authsign(&srv_log, secret_key,
				op->pkt_data, op->pkt_len - SHA_DIGEST_LENGTH,
				foot->sha);
		if (ret) {
			HAIL_ERR(&srv_log, "%s: authsign failed: %d",
				 __func__, ret);
			goto err_out;
		}
	}

	/* send packets */
	for (tmp_list = g_list_first(new_pkts);
	     tmp_list;
	     tmp_list = g_list_next(tmp_list)) {
		struct session_outpkt *op =
			(struct session_outpkt *) tmp_list->data;
		udp_tx(sess->sock_fd, (struct sockaddr *) &sess->addr,
			sess->addr_len, op->pkt_data, op->pkt_len);
	}

	session_outq(sess, new_pkts);

	return true;

err_out:
	for (tmp_list = g_list_first(new_pkts); tmp_list;
	     tmp_list = g_list_next(tmp_list)) {
		struct session_outpkt *op;
		op = (struct session_outpkt *)tmp_list->data;
		op_unref(op);
	}
	g_list_free(new_pkts);
	return false;
}

void sess_sendresp_generic(struct session *sess, enum cle_err_codes code)
{
	struct cld_msg_generic_resp resp;
	resp.code = code;
	resp.xid_in = sess->msg_xid;

	sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_generic_resp,
		     (void *)&resp, sess->msg_op, NULL, NULL);
}

void msg_ack(struct session *sess, uint64_t seqid)
{
	GList *tmp, *tmp1;
	struct session_outpkt *op;

	if (!sess->out_q)
		return;

	/* look through output queue */
	tmp = sess->out_q;
	while (tmp) {
		uint64_t op_seqid;
		struct cld_pkt_ftr *foot;
		tmp1 = tmp;
		tmp = tmp->next;

		op = tmp1->data;
		foot = (struct cld_pkt_ftr *)
			(op->pkt_data + (op->pkt_len - CLD_PKT_FTR_LEN));
		op_seqid = le64_to_cpu(foot->seqid);

		/* if matching seqid found, we ack'd a message in out_q */
		if (seqid != op_seqid)
			continue;

		HAIL_DEBUG(&srv_log, "    expiring seqid %llu",
			   (unsigned long long) op_seqid);

		/* remove and delete the ack'd msg; call ack'd callback */
		sess->out_q = g_list_delete_link(sess->out_q, tmp1);

		if (op->done_cb)
			op->done_cb(op);
		op_unref(op);
	}

	if (!sess->out_q)
		cld_timer_del(&cld_srv.timers, &sess->retry_timer);
}

void msg_new_sess(int sock_fd, const struct client *cli,
		  const struct pkt_info *info)
{
	const struct cld_pkt_hdr *pkt = info->pkt;
	DB *db = cld_srv.cldb.sessions;
	struct raw_session raw_sess;
	struct session *sess = NULL;
	DBT key, val;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	struct cld_msg_generic_resp resp;

	sess = session_new();
	if (!sess) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	/* build raw_session database record */
	memcpy(sess->sid, &pkt->sid, sizeof(sess->sid));
	memcpy(&sess->addr, &cli->addr, sizeof(sess->addr));

	snprintf(sess->user, sizeof(sess->user), "%s",
		pkt->user);

	sess->sock_fd = sock_fd;
	sess->addr_len = cli->addr_len;
	strncpy(sess->ipaddr, cli->addr_host, sizeof(sess->ipaddr));
	sess->last_contact = current_time.tv_sec;
	sess->next_seqid_in = info->seqid + 1;

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

	HAIL_DEBUG(&srv_log, "%s: created new session " SIDFMT " with "
		   "sess->next_seqid_in = %llu",
		   __func__, SIDARG(sess->sid),
		   (unsigned long long) sess->next_seqid_in);

	g_hash_table_insert(cld_srv.sessions, sess->sid, sess);

	/* begin session timer */
	cld_timer_add(&cld_srv.timers, &sess->timer,
		      time(NULL) + (CLD_SESS_TIMEOUT / 2));

	/* send new-sess reply */
	resp.code = CLE_OK;
	resp.xid_in = info->xid;
	sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_generic_resp,
		     (void *)&resp, CMO_NEW_SESS, NULL, NULL);

	return;

err_out:
	session_free(sess, true);

	HAIL_DEBUG(&srv_log, "%s err: sid " SIDFMT ", op %s",
		   __func__,
		   (unsigned long long) pkt->sid, __cld_opstr(CMO_NEW_SESS));

	resp.code = resp_rc;
	resp.xid_in = info->xid;
	simple_sendmsg(sock_fd, cli, pkt->sid, pkt->user, 0xdeadbeef,
		       (xdrproc_t)xdr_cld_msg_generic_resp, (void *)&resp,
		       CMO_NEW_SESS);

	HAIL_DEBUG(&srv_log, "NEW-SESS failed: %d", resp_rc);
}

static void end_sess_done(struct session_outpkt *outpkt)
{
	session_trash(outpkt->sess);
}

void msg_end_sess(struct session *sess, uint64_t xid)
{
	struct cld_msg_generic_resp resp;

	/* do nothing; let message acknowledgement via
	 * end_sess_done mark session dead
	 */
	resp.code = CLE_OK;
	resp.xid_in = xid;
	sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_generic_resp,
			&resp, CMO_END_SESS,
			end_sess_done, NULL);
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

		HAIL_DEBUG(&srv_log, " loaded sid " SIDFMT
			   " next seqid %llu/%llu",
			   SIDARG(sess->sid),
			   (unsigned long long) le64_to_cpu(sess->next_seqid_out),
			   (unsigned long long) le64_to_cpu(sess->next_seqid_in));

		g_hash_table_insert(ss, sess->sid, sess);

		/* begin session timer */
		cld_timer_add(&cld_srv.timers, &sess->timer,
			      time(NULL) + (CLD_SESS_TIMEOUT / 2));
	}

	cur->close(cur);
	return 0;
}



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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "cld.h"

static void session_retry(int fd, short events, void *userdata);
static void session_timeout(int fd, short events, void *userdata);

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

	evtimer_set(&sess->timer, session_timeout, sess);
	evtimer_set(&sess->retry_timer, session_retry, sess);

	return sess;
}

static void session_free(struct session *sess)
{
	if (!sess)
		return;

	g_hash_table_remove(cld_srv.sessions, sess->sid);

	evtimer_del(&sess->timer);
	evtimer_del(&sess->retry_timer);

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
	bool first_loop = true;

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

	while (1) {
		struct raw_lock *l;
		int gflags;

		if (first_loop) {
			first_loop = false;
			gflags = DB_SET;
		} else
			gflags = DB_NEXT_DUP;

		/* search for first/next matching lock */
		rc = cur->get(cur, &pkey, &pval, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				db_locks->err(db_locks, rc, "curget2");
			break;
		}

		l = pval.data;

		/* if not our sid, check for pending lock acquisitions */
		if (!lmatch(l, sid, fh)) {
			if (GUINT32_FROM_LE(l->flags) & CLFL_PENDING)
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
	int rc, i;
	DBT pkey, pval;
	bool first_loop = true;
	GArray *locks, *waiters;

	memcpy(&hkey.sid, sess->sid, sizeof(sess->sid));
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

	/* loop through handles, deleting those with our sid */
	while (1) {
		int gflags;
		struct raw_handle *h;

		if (first_loop) {
			first_loop = false;
			gflags = DB_SET_RANGE;
		} else
			gflags = DB_NEXT;

		/* search for first/next matching handle */
		rc = cur->get(cur, &pkey, &pval, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				db_handles->err(db_handles, rc, "curget1");
			break;
		}

		h = pval.data;

		/* verify same sid */
		if (memcmp(h->sid, sess->sid, sizeof(sess->sid)))
			break;

		if (GUINT32_FROM_LE(h->mode) & COM_LOCK) {
			cldino_t inum;

			inum = cldino_from_le(h->inum);
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
		syslog(LOG_WARNING, "failed to remove session");

	return rc;
}

static void session_ping(struct session *sess)
{
	struct cld_msg_hdr resp;
	uint64_t msgid;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	msgid = tv.tv_sec ^ tv.tv_usec;
	msgid = GUINT64_TO_LE(msgid);

	memset(&resp, 0, sizeof(resp));
	memcpy(&resp.magic, CLD_MAGIC, strlen(CLD_MAGIC));
	memcpy(&resp.msgid, &msgid, sizeof(msgid));
	memcpy(&resp.sid, &sess->sid, CLD_SID_SZ);
	resp.op = cmo_ping;

	sess_sendmsg(sess, &resp, sizeof(resp), true);

	sess->ping_open = true;
}

static void session_timeout(int fd, short events, void *userdata)
{
	struct session *sess = userdata;
	uint64_t sess_expire, *tmp64;
	int rc;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	sess_expire = sess->last_contact + CLD_SESS_TIMEOUT;
	if (sess_expire > current_time) {
		struct timeval tv;

		if (!sess->ping_open &&
		    (sess_expire > (sess->last_contact + (CLD_SESS_TIMEOUT / 2))))
			session_ping(sess);

		tv.tv_sec = ((sess_expire - current_time) / 2) + 1;
		tv.tv_usec = 0;

		if (evtimer_add(&sess->timer, &tv) < 0)
			syslog(LOG_WARNING, "evtimer_add session_tmout failed");
		else
			return;	/* timer added; do not time out session */
	}

	tmp64 = (uint64_t *) &sess->sid;
	syslog(LOG_INFO, "session timeout, addr %s id %016llX",
		sess->ipaddr,
		(unsigned long long) GUINT64_FROM_LE(*tmp64));

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
	memcpy(raw, sess, CLD_SID_SZ + CLD_IPADDR_SZ);
	raw->last_contact = GUINT64_TO_LE(sess->last_contact);
	raw->next_fh = GUINT64_TO_LE(sess->next_fh);
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

static void om_free(struct session_outmsg *om)
{
	if (!om)
		return;

	free(om->msg);
	free(om);
}

static int sess_retry_output(struct session *sess)
{
	GList *tmp, *tmp1;
	struct session_outmsg *om;
	int rc = 0;

	tmp = sess->out_q;
	while (tmp) {
		tmp1 = tmp;
		tmp = tmp->next;

		om = tmp1->data;

		if (current_time < om->next_retry)
			continue;

		rc = udp_tx(sess->sock, (struct sockaddr *) &sess->addr,
			    sess->addr_len, om->msg, om->msglen);
		if (rc)
			break;

		om->next_retry *= 2;
	}

	return rc;
}

static void session_retry(int fd, short events, void *userdata)
{
	struct session *sess = userdata;
	struct timeval tv = { CLD_RETRY_START, 0 };

	sess_retry_output(sess);

	if (evtimer_add(&sess->retry_timer, &tv) < 0)
		syslog(LOG_WARNING, "failed to re-add retry timer");
}

bool sess_sendmsg(struct session *sess, void *msg_, size_t msglen,
		  bool copy_msg)
{
	void *msg;
	struct session_outmsg *om;

	om = malloc(sizeof(*om));
	if (!om)
		return false;

	if (copy_msg) {
		msg = malloc(msglen);
		if (!msg) {
			free(om);
			return false;
		}

		memcpy(msg, msg_, msglen);
	} else
		msg = msg_;

	om->msg = msg;
	om->msglen = msglen;
	om->next_retry = current_time + CLD_RETRY_START;

	/* if out_q empty, start retry timer */
	if (!sess->out_q) {
		struct timeval tv = { CLD_RETRY_START, 0 };
		if (evtimer_add(&sess->retry_timer, &tv) < 0)
			syslog(LOG_WARNING, "retry timer start failed");
	}

	sess->out_q = g_list_append(sess->out_q, om);

	udp_tx(sess->sock, (struct sockaddr *) &sess->addr,
	       sess->addr_len, msg, msglen);

	return true;
}

bool sid_sendmsg(const uint8_t *sid, void *msg_, size_t msglen, bool copy_msg)
{
	struct session *sess;

	sess = g_hash_table_lookup(cld_srv.sessions, sid);
	if (!sess)
		return false;

	return sess_sendmsg(sess, msg_, msglen, copy_msg);
}

bool msg_ack(struct msg_params *mp)
{
	struct cld_msg_hdr *outmsg, *msg = mp->msg;
	GList *tmp, *tmp1;
	struct session *sess = mp->sess;
	struct session_outmsg *om;

	if (!sess->out_q)
		return true;

	/* look through output queue */
	tmp = sess->out_q;
	while (tmp) {
		tmp1 = tmp;
		tmp = tmp->next;

		om = tmp1->data;
		outmsg = om->msg;

		/* if matching msgid found, we ack'd a message in out_q */
		if (memcmp(msg->msgid, outmsg->msgid, sizeof(msg->msgid)))
			continue;

		if (outmsg->op == cmo_ping)
			sess->ping_open = false;

		/* remove and delete the ack'd msg */
		sess->out_q = g_list_delete_link(sess->out_q, tmp1);
		om_free(om);
	}

	if (!sess->out_q)
		if (evtimer_del(&sess->retry_timer) < 0)
			syslog(LOG_WARNING, "failed to delete retry timer");

	return true;
}

bool msg_new_sess(struct msg_params *mp, const struct client *cli)
{
	struct cld_msg_hdr *msg = mp->msg;
	DB *db = cld_srv.cldb.sessions;
	struct raw_session raw_sess;
	struct session *sess;
	DB_TXN *txn = mp->txn;
	DBT key, val;
	int rc;
	struct timeval tv;

	sess = session_new();
	if (!sess)
		/* note, the client does not get response if we OOM here */
		return false;

	/* build raw_session database record */
	memcpy(&sess->sid, &msg->sid, sizeof(sess->sid));
	memcpy(&sess->addr, &cli->addr, sizeof(sess->addr));
	sess->sock = mp->sock;
	sess->addr_len = cli->addr_len;
	strncpy(sess->ipaddr, cli->addr_host, sizeof(sess->ipaddr));
	sess->last_contact = current_time;

	session_encode(&raw_sess, sess);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: sid */
	key.data = &raw_sess.sid;
	key.size = sizeof(raw_sess.sid);

	val.data = &raw_sess;
	val.size = sizeof(raw_sess);

	/* attempt to store session; if session already exists,
	 * this should fail
	 */
	rc = db->put(db, txn, &key, &val, DB_NOOVERWRITE);
	if (rc)
		goto err_out;

	g_hash_table_insert(cld_srv.sessions, sess->sid, sess);

	/* begin session timer */
	tv.tv_sec = CLD_SESS_TIMEOUT / 2;
	tv.tv_usec = 0;
	if (evtimer_add(&sess->timer, &tv) < 0) {
		syslog(LOG_WARNING, "evtimer_add session_new failed");
		goto err_out;
	}

	resp_ok(mp->sock, sess, msg);
	return true;

err_out:
	/* note: no response to client, in new-session error case */
	session_free(sess);
	return false;
}



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
#include <syslog.h>
#include "cld.h"

static void session_retry(int fd, short events, void *userdata);

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

	return (memcmp(a->sid, b->sid, CLD_CLID_SZ) == 0);
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
	memcpy(&resp.sid, &sess->sid, CLD_ID_SZ);
	resp.op = cmo_ping;

	sess_sendmsg(sess, &resp, sizeof(resp), true);

	sess->ping_open = true;
}

static void session_timeout(int fd, short events, void *userdata)
{
	struct session *sess = userdata;
	uint64_t sess_expire, *tmp64;

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

	/* FIXME */
	(void) sess;
}

static struct session *session_new(void)
{
	struct session *sess;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return NULL;

	sess->handles = g_array_new(FALSE, FALSE, sizeof(uint64_t));

	evtimer_set(&sess->timer, session_timeout, sess);
	evtimer_set(&sess->retry_timer, session_retry, sess);

	return sess;
}

static void session_encode(struct raw_session *raw, const struct session *sess)
{
	uint64_t *hsrc, *hdest;
	int i;
	void *p;

	memcpy(raw, sess, CLD_CLID_SZ + CLD_IPADDR_SZ);
	raw->last_contact = GUINT64_TO_LE(sess->last_contact);
	raw->next_fh = GUINT64_TO_LE(sess->next_fh);
	raw->n_handles = GUINT32_TO_LE(sess->handles->len);

	hsrc = (uint64_t *) sess->handles->data;

	p = raw;
	p += sizeof(*raw);
	hdest = p;

	for (i = 0; i < sess->handles->len; i++)
		hdest[i] = GUINT64_TO_LE(hsrc[i]);
}

struct raw_session *session_new_raw(const struct session *sess)
{
	struct raw_session *raw_sess;
	size_t alloc_len;

	alloc_len = sizeof(*raw_sess) + (sizeof(uint64_t) * sess->handles->len);
	raw_sess = malloc(alloc_len);
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

bool msg_ack(struct server_socket *sock, DB_TXN *txn,
	     struct session *sess, uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_hdr *outmsg, *msg = (struct cld_msg_hdr *) raw_msg;
	GList *tmp, *tmp1;
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

bool msg_new_cli(struct server_socket *sock, DB_TXN *txn,
		 const struct client *cli, uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_hdr *msg = (struct cld_msg_hdr *) raw_msg;
	DB *db = cld_srv.cldb.sessions;
	struct raw_session raw_sess;
	struct session *sess;
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
	sess->sock = sock;
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

	resp_ok(sock, sess, msg);
	return true;

err_out:
	/* note: no response to client, in new-session error case */
	free(sess);
	return false;
}


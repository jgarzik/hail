
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <cld-private.h>
#include <cldc.h>
#include <syslog.h>

enum {
	CLDC_MSG_EXPIRE		= 5 * 60,
	CLDC_MSG_SCAN		= 60,
	CLDC_MSG_RETRY		= 5,
	CLDC_MSG_REMEMBER	= 25,
	CLDC_SESS_EXPIRE	= 2 * 60,
};

static const char *user_key(struct cldc_session *sess, const char *user);
static int sess_send_pkt(struct cldc_session *sess,
			 const struct cld_packet *pkt, size_t pkt_len);

static const struct cld_msg_hdr def_msg_ack = {
	.magic		= CLD_MSG_MAGIC,
	.op		= CMO_ACK,
};

#ifndef HAVE_STRNLEN
static size_t strnlen(const char *s, size_t maxlen)
{
	int len = 0;

	if (!s)
		return 0;

	while ((len < maxlen) && (*s)) {
		s++;
		len++;
	}

	return len;
}
#endif
#ifndef EBADRQC
#define EBADRQC 56
#endif
#ifndef EBADSLT
#define EBADSLT 57
#endif
#ifndef EBADE
#define EBADE 52
#endif

static void cldc_errlog(int prio, const char *fmt, ...)
{
	char buf[200];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, 200, fmt, ap);
	fprintf(stderr, "%s\n", buf);
	va_end(ap);
}

static int ack_seqid(struct cldc_session *sess, uint64_t seqid_le)
{
	struct cld_packet *pkt;
	struct cld_msg_hdr *resp;
	size_t pkt_len;
	int ret;
	const char *secret_key;

	pkt_len = sizeof(*pkt) + sizeof(*resp) + SHA_DIGEST_LENGTH;
	pkt = alloca(pkt_len);
	memset(pkt, 0, pkt_len);

	memcpy(pkt->magic, CLD_PKT_MAGIC, CLD_MAGIC_SZ);
	pkt->seqid = seqid_le;
	memcpy(pkt->sid, sess->sid, CLD_SID_SZ);
	pkt->flags = cpu_to_le32(CPF_FIRST | CPF_LAST);
	strncpy(pkt->user, sess->user, CLD_MAX_USERNAME - 1);

	resp = (struct cld_msg_hdr *) (pkt + 1);
	memcpy(resp, &def_msg_ack, sizeof(*resp));

	secret_key = user_key(sess, sess->user);
	ret = __cld_authsign(&sess->log, secret_key,
			     pkt, pkt_len - SHA_DIGEST_LENGTH,
			     (uint8_t *)pkt + pkt_len - SHA_DIGEST_LENGTH);
	if (ret) {
		HAIL_ERR(&sess->log, "%s: authsign failed: %d",
			 __func__, ret);
		return ret;
	}

	return sess_send_pkt(sess, pkt, pkt_len);
}

static int rxmsg_generic(struct cldc_session *sess,
			 const struct cld_packet *pkt,
			 const void *msgbuf, size_t buflen)
{
	const struct cld_msg_resp *resp = msgbuf;
	struct cldc_msg *req = NULL;
	GList *tmp;

	if (buflen < sizeof(*resp))
		return -1008;

	/* Find out which outbound message this was a response to */
	tmp = sess->out_msg;
	while (tmp) {
		req = tmp->data;

		HAIL_DEBUG(&sess->log, "%s: comparing req->xid (%llu) "
			   "with resp.xid_in (%llu)",
			   __func__,
			   (unsigned long long) le64_to_cpu(req->xid),
			   (unsigned long long) le64_to_cpu(resp->xid_in));

		if (req->xid == resp->xid_in)
			break;
		tmp = tmp->next;
	}
	if (!tmp) {
		HAIL_DEBUG(&sess->log, "%s: no match found with "
			   "xid_in %llu",
			   __func__,
			   (unsigned long long) le64_to_cpu(resp->xid_in));
		return -1005;
	}

	if (req->done) {
		HAIL_DEBUG(&sess->log, "%s: re-acking", __func__);
	} else {
		HAIL_DEBUG(&sess->log, "%s: issuing completion, acking",
			   __func__);

		req->done = true;

		if (req->cb) {
			ssize_t rc = req->cb(req, msgbuf, buflen, true);
			if (rc < 0)
				return rc;
		}
	}

	return ack_seqid(sess, pkt->seqid);
}

static int rxmsg_ack_frag(struct cldc_session *sess,
			  const struct cld_packet *pkt,
			  const void *msgbuf, size_t buflen)
{
	const struct cld_msg_ack_frag *ack_msg = msgbuf;
	GList *tmp;

	if (buflen < sizeof(*ack_msg))
		return -1008;

	HAIL_INFO(&sess->log, "%s: seqid %llu, want to ack",
		  __func__,
		  (unsigned long long) ack_msg->seqid);

	tmp = sess->out_msg;
	while (tmp) {
		struct cldc_msg *req;
		int i;

		req = tmp->data;
		tmp = tmp->next;

		for (i = 0; i < req->n_pkts; i++) {
			struct cldc_pkt_info *pi;
			uint64_t seqid;

			pi = req->pkt_info[i];
			if (!pi)
				continue;
			seqid = pi->pkt.seqid;
			if (seqid != ack_msg->seqid)
				continue;

			HAIL_DEBUG(&sess->log, "%s: seqid %llu, expiring",
				   __func__,
				   (unsigned long long) ack_msg->seqid);

			req->pkt_info[i] = NULL;
			free(pi);
		}
	}

	return 0;
}

static int rxmsg_event(struct cldc_session *sess,
		       const struct cld_packet *pkt,
		       const void *msgbuf, size_t buflen)
{
	const struct cld_msg_event *ev = msgbuf;
	struct cldc_fh *fh = NULL;
	int i;

	if (buflen < sizeof(*ev))
		return -1008;

	for (i = 0; i < sess->fh->len; i++) {
		fh = &g_array_index(sess->fh, struct cldc_fh, i);
		if (fh->fh_le == ev->fh)
			break;
		else
			fh = NULL;
	}

	if (!fh)
		return -1011;

	sess->ops->event(sess->private, sess, fh, le32_to_cpu(ev->events));

	return 0;
}

static int rxmsg_not_master(struct cldc_session *sess,
			    const struct cld_packet *pkt,
			    const void *msgbuf, size_t buflen)
{
	HAIL_DEBUG(&sess->log, "FIXME: not-master message received");
	return -1055;	/* FIXME */
}

static void cldc_msg_free(struct cldc_msg *msg)
{
	int i;

	if (!msg)
		return;

	for (i = 0; i < msg->n_pkts; i++)
		free(msg->pkt_info[i]);

	free(msg);
}

static void sess_expire_outmsg(struct cldc_session *sess, time_t current_time)
{
	GList *tmp, *tmp1;

	tmp = sess->out_msg;
	while (tmp) {
		struct cldc_msg *msg;

		tmp1 = tmp;
		tmp = tmp->next;

		msg = tmp1->data;
		if (current_time > msg->expire_time) {
			cldc_msg_free(msg);
			sess->out_msg = g_list_delete_link(sess->out_msg, tmp1);
		}
	}

	sess->msg_scan_time = current_time + CLDC_MSG_SCAN;
}

static const char *user_key(struct cldc_session *sess, const char *user)
{
	if (!sess || !user || !*user ||
	    (strnlen(user, CLD_MAX_USERNAME) >= CLD_MAX_USERNAME))
		return NULL;
	if (strcmp(sess->user, user))
		return NULL;

	return sess->secret_key;
}

static int cldc_receive_msg(struct cldc_session *sess,
			    const struct cld_packet *pkt,
			    size_t pkt_len)
{
	const struct cld_msg_hdr *msg = (struct cld_msg_hdr *) sess->msg_buf;
	size_t msglen = sess->msg_buf_len;

	if (memcmp(msg->magic, CLD_MSG_MAGIC, sizeof(msg->magic))) {
		HAIL_DEBUG(&sess->log, "%s: bad msg magic", __func__);
		return -EPROTO;
	}

	switch(msg->op) {
	case CMO_NOP:
	case CMO_CLOSE:
	case CMO_DEL:
	case CMO_LOCK:
	case CMO_UNLOCK:
	case CMO_TRYLOCK:
	case CMO_PUT:
	case CMO_NEW_SESS:
	case CMO_END_SESS:
	case CMO_OPEN:
	case CMO_GET_META:
	case CMO_GET:
		return rxmsg_generic(sess, pkt, msg, msglen);
	case CMO_NOT_MASTER:
		return rxmsg_not_master(sess, pkt, msg, msglen);
	case CMO_ACK_FRAG:
		return rxmsg_ack_frag(sess, pkt, msg, msglen);
	case CMO_EVENT:
		return rxmsg_event(sess, pkt, msg, msglen);
	case CMO_PING:
		return ack_seqid(sess, pkt->seqid);
	case CMO_ACK:
		return -EBADRQC;
	}

	/* unknown op code */
	return -EBADRQC;
}

int cldc_receive_pkt(struct cldc_session *sess,
		     const void *net_addr, size_t net_addrlen,
		     const void *pktbuf, size_t pkt_len)
{
	const struct cld_packet *pkt = pktbuf;
	const struct cld_msg_hdr *msg = (struct cld_msg_hdr *) (pkt + 1);
	const char *secret_key;
	size_t msglen;
	struct timeval tv;
	time_t current_time;
	uint64_t seqid;
	uint32_t pkt_flags;
	bool first_frag, last_frag, have_new_sess, no_seqid;
	bool have_get;
	int ret;

	gettimeofday(&tv, NULL);
	current_time = tv.tv_sec;

	if (pkt_len < (sizeof(*pkt) + SHA_DIGEST_LENGTH)) {
		HAIL_DEBUG(&sess->log, "%s: msg too short", __func__);
		return -EPROTO;
	}

	msglen = pkt_len - sizeof(*pkt) - SHA_DIGEST_LENGTH;

	pkt_flags = le32_to_cpu(pkt->flags);
	first_frag = pkt_flags & CPF_FIRST;
	last_frag = pkt_flags & CPF_LAST;
	have_get = first_frag && (msg->op == CMO_GET);
	have_new_sess = first_frag && (msg->op == CMO_NEW_SESS);
	no_seqid = first_frag && ((msg->op == CMO_NOT_MASTER) ||
				  (msg->op == CMO_ACK_FRAG));

	if (sess->log.verbose) {
		if (have_get) {
			struct cld_msg_get_resp *dp;
			dp = (struct cld_msg_get_resp *) msg;
			HAIL_DEBUG(&sess->log, "%s(len %u, op %s"
				   ", seqid %llu, user %s, size %u)",
				   __func__,
				   (unsigned int) pkt_len,
				   __cld_opstr(msg->op),
				   (unsigned long long) le64_to_cpu(pkt->seqid),
				   pkt->user,
				   le32_to_cpu(dp->size));
		} else if (have_new_sess) {
			struct cld_msg_resp *dp;
			dp = (struct cld_msg_resp *) msg;
			HAIL_DEBUG(&sess->log, "%s(len %u, op %s"
				   ", seqid %llu, user %s, xid_in %llu)",
				   __func__,
				   (unsigned int) pkt_len,
				   __cld_opstr(msg->op),
				   (unsigned long long) le64_to_cpu(pkt->seqid),
				   pkt->user,
				   (unsigned long long) le64_to_cpu(dp->xid_in));
		} else {
			HAIL_DEBUG(&sess->log, "%s(len %u, "
				   "flags %s%s, op %s, seqid %llu, user %s)",
				   __func__,
				   (unsigned int) pkt_len,
				   first_frag ? "F" : "",
				   last_frag ? "L" : "",
				   first_frag ? __cld_opstr(msg->op) : "n/a",
				   (unsigned long long) le64_to_cpu(pkt->seqid),
				   pkt->user);
		}
	}

	if (memcmp(pkt->magic, CLD_PKT_MAGIC, sizeof(pkt->magic))) {
		HAIL_DEBUG(&sess->log, "%s: bad pkt magic", __func__);
		return -EPROTO;
	}

	/* check HMAC signature */
	secret_key = user_key(sess, pkt->user);
	ret = __cld_authcheck(&sess->log, secret_key,
			      pkt, pkt_len - SHA_DIGEST_LENGTH,
			      (uint8_t *)pkt + pkt_len - SHA_DIGEST_LENGTH);
	if (ret) {
		HAIL_DEBUG(&sess->log, "%s: invalid auth (ret=%d)",
			   __func__, ret);
		return -EACCES;
	}

	/* verify stored server addr matches pkt addr */
	if (((sess->addr_len != net_addrlen) ||
	    memcmp(sess->addr, net_addr, net_addrlen))) {
		HAIL_DEBUG(&sess->log, "%s: server address mismatch", __func__);
		return -EBADE;
	}

	/* expire old sess outgoing messages */
	if (current_time >= sess->msg_scan_time)
		sess_expire_outmsg(sess, current_time);

	if (first_frag)
		sess->msg_buf_len = 0;

	if ((sess->msg_buf_len + msglen) > CLD_MAX_MSG_SZ) {
		HAIL_DEBUG(&sess->log, "%s: bad pkt length", __func__);
		return -EPROTO;
	}

	memcpy(sess->msg_buf + sess->msg_buf_len, msg, msglen);
	sess->msg_buf_len += msglen;

	/* verify (or set, for new-sess) sequence id */
	seqid = le64_to_cpu(pkt->seqid);
	if (have_new_sess) {
		sess->next_seqid_in = seqid + 1;
		sess->next_seqid_in_tr =
			sess->next_seqid_in - CLDC_MSG_REMEMBER;

		HAIL_DEBUG(&sess->log, "%s: "
			   "setting next_seqid_in to %llu",
			   __func__, (unsigned long long) seqid);
	} else if (!no_seqid) {
		if (seqid != sess->next_seqid_in) {
			if (seqid_in_range(seqid,
					   sess->next_seqid_in_tr,
					   sess->next_seqid_in))
				return ack_seqid(sess, pkt->seqid);

			HAIL_DEBUG(&sess->log, "%s: bad seqid %llu",
				   __func__, (unsigned long long) seqid);
			return -EBADSLT;
		}
		sess->next_seqid_in++;
		sess->next_seqid_in_tr++;
	}

	sess->expire_time = current_time + CLDC_SESS_EXPIRE;

	if (!last_frag)
		return sess ? ack_seqid(sess, pkt->seqid) : 0;

	return cldc_receive_msg(sess, pkt, pkt_len);
}

static void sess_next_seqid(struct cldc_session *sess, uint64_t *seqid)
{
	uint64_t rc = cpu_to_le64(sess->next_seqid_out++);
	*seqid = rc;
}

static struct cldc_msg *cldc_new_msg(struct cldc_session *sess,
				     const struct cldc_call_opts *copts,
				     enum cld_msg_ops op,
				     size_t msg_len)
{
	struct cldc_msg *msg;
	struct cld_msg_hdr *hdr;
	struct timeval tv;
	int i, data_left;
	void *p;

	gettimeofday(&tv, NULL);

	/* Create cldc_msg */
	msg = calloc(1, sizeof(*msg) + msg_len);
	if (!msg)
		return NULL;

	__cld_rand64(&msg->xid);

	msg->sess = sess;

	if (copts)
		memcpy(&msg->copts, copts, sizeof(msg->copts));

	msg->expire_time = tv.tv_sec + CLDC_MSG_EXPIRE;

	msg->data_len = msg_len;

	msg->n_pkts = msg_len / CLD_MAX_PKT_MSG_SZ;
	msg->n_pkts += ((msg_len % CLD_MAX_PKT_MSG_SZ) ? 1 : 0);

	p = msg->data;
	data_left = msg_len;
	for (i = 0; i < msg->n_pkts; i++) {
		struct cldc_pkt_info *pi;
		int pkt_len;

		pkt_len = MIN(data_left, CLD_MAX_PKT_MSG_SZ);

		pi = calloc(1, sizeof(*pi) + pkt_len + SHA_DIGEST_LENGTH);
		if (!pi)
			goto err_out;

		pi->pkt_len = pkt_len;

		memcpy(pi->pkt.magic, CLD_PKT_MAGIC, CLD_MAGIC_SZ);
		memcpy(pi->pkt.sid, sess->sid, CLD_SID_SZ);
		strncpy(pi->pkt.user, sess->user, CLD_MAX_USERNAME - 1);

		if (i == 0)
			pi->pkt.flags |= cpu_to_le32(CPF_FIRST);
		if (i == (msg->n_pkts - 1))
			pi->pkt.flags |= cpu_to_le32(CPF_LAST);

		msg->pkt_info[i] = pi;
		data_left -= pkt_len;
	}

	hdr = (struct cld_msg_hdr *) &msg->data[0];
	memcpy(&hdr->magic, CLD_MSG_MAGIC, CLD_MAGIC_SZ);
	hdr->op = op;
	hdr->xid = msg->xid;

	return msg;

err_out:
	cldc_msg_free(msg);
	return NULL;
}

static void sess_msg_drop(struct cldc_session *sess)
{
	GList *tmp = sess->out_msg;
	struct cldc_msg *msg;

	while (tmp) {
		msg = tmp->data;
		tmp = tmp->next;

		if (!msg->done && msg->cb)
			msg->cb(msg, NULL, 0, false);

		cldc_msg_free(msg);
	}

	g_list_free(sess->out_msg);
	sess->out_msg = NULL;
}

static void sess_expire(struct cldc_session *sess)
{
	sess->expired = true;
	sess_msg_drop(sess);

	sess->ops->timer_ctl(sess->private, false, NULL, NULL, 0);

	sess->ops->event(sess->private, sess, NULL, CE_SESS_FAILED);
	/* FIXME why not sess_free here */
}

static int sess_send_pkt(struct cldc_session *sess,
			 const struct cld_packet *pkt, size_t pkt_len)
{
	if (sess->log.verbose) {
		uint32_t flags = le32_to_cpu(pkt->flags);
		bool first = (flags & CPF_FIRST);
		bool last = (flags & CPF_LAST);
		uint8_t op = CMO_NOP;

		if (first) {
			struct cld_msg_hdr *hdr;

			hdr = (struct cld_msg_hdr *) (pkt + 1);
			op = hdr->op;
		}

		HAIL_DEBUG(&sess->log,
			   "%s(len %zu, flags %s%s, "
			   "op %s, seqid %llu)",
			   __func__,
			   pkt_len,
			   first ? "F" : "",
			   last ? "L" : "",
			   first ? __cld_opstr(op) : "n/a",
			   (unsigned long long) le64_to_cpu(pkt->seqid));
	}

	return sess->ops->pkt_send(sess->private,
				   sess->addr, sess->addr_len,
				   pkt, pkt_len);
}

static int sess_timer(struct cldc_session *sess, void *priv)
{
	GList *tmp = sess->out_msg;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (tv.tv_sec > sess->expire_time) {
		sess_expire(sess);
		return 0;
	}

	while (tmp) {
		struct cldc_msg *msg;
		int i;

		msg = tmp->data;
		tmp = tmp->next;

		if (msg->done)
			continue;

		for (i = 0; i < msg->n_pkts; i++) {
			struct cldc_pkt_info *pi;
			int total_pkt_len;

			pi = msg->pkt_info[i];
			if (!pi)
				continue;

			total_pkt_len = sizeof(struct cld_packet) +
					pi->pkt_len + SHA_DIGEST_LENGTH;

			pi->retries++;

			sess_send_pkt(sess, &pi->pkt, total_pkt_len);
		}
	}

	sess->ops->timer_ctl(sess->private, true, sess_timer, sess,
			     CLDC_MSG_RETRY);
	return CLDC_MSG_RETRY;
}

static int sess_send(struct cldc_session *sess, struct cldc_msg *msg)
{
	int ret, i;
	int data_left;
	void *p;
	const char *secret_key;

	secret_key = user_key(sess, sess->user);

	p = msg->data;
	data_left = msg->data_len;
	for (i = 0; i < msg->n_pkts; i++) {
		struct cldc_pkt_info *pi;
		int total_pkt_len;

		pi = msg->pkt_info[i];
		memcpy(pi->data, p, pi->pkt_len);

		total_pkt_len = sizeof(struct cld_packet) +
				pi->pkt_len + SHA_DIGEST_LENGTH;

		/* Add the sequence number to the end of the packet */
		sess_next_seqid(sess, &pi->pkt.seqid);

		p += pi->pkt_len;
		data_left -= pi->pkt_len;

		/* Add the signature to the end of the packet */
		ret = __cld_authsign(&sess->log, secret_key,
				     &pi->pkt, total_pkt_len-SHA_DIGEST_LENGTH,
				     ((uint8_t *)&pi->pkt + total_pkt_len) -
				    	SHA_DIGEST_LENGTH);
		if (ret)
			return ret;

		/* attempt first send */
		if (sess_send_pkt(sess, &pi->pkt, total_pkt_len) < 0)
			return -EIO;
	}

	/* add to list of outgoing packets, waiting to be ack'd */
	sess->out_msg = g_list_prepend(sess->out_msg, msg);

	return 0;
}

static void sess_free(struct cldc_session *sess)
{
	GList *tmp;

	if (!sess)
		return;

	if (sess->fh)
		g_array_free(sess->fh, TRUE);

	tmp = sess->out_msg;
	while (tmp) {
		cldc_msg_free(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(sess->out_msg);

	memset(sess, 0, sizeof(*sess));
	free(sess);
}

static ssize_t end_sess_cb(struct cldc_msg *msg, const void *resp_p,
			   size_t resp_len, bool ok)
{
	const struct cld_msg_resp *resp = resp_p;
	enum cle_err_codes resp_rc = CLE_OK;

	if (!ok)
		resp_rc = CLE_TIMEOUT;
	else
		resp_rc = le32_to_cpu(resp->code);

	if (msg->copts.cb)
		return msg->copts.cb(&msg->copts, resp_rc);

	sess_free(msg->sess);
	return 0;
}

int cldc_end_sess(struct cldc_session *sess, const struct cldc_call_opts *copts)
{
	struct cldc_msg *msg;

	if (!sess->confirmed)
		return -EINVAL;

	/* create END-SESS message */
	msg = cldc_new_msg(sess, copts, CMO_END_SESS,
			   sizeof(struct cld_msg_hdr));
	if (!msg)
		return -ENOMEM;

	msg->cb = end_sess_cb;

	return sess_send(sess, msg);
}

static ssize_t new_sess_cb(struct cldc_msg *msg, const void *resp_p,
			   size_t resp_len, bool ok)
{
	struct cldc_session *sess = msg->sess;
	const struct cld_msg_resp *resp = resp_p;
	enum cle_err_codes resp_rc = CLE_OK;

	if (!ok)
		resp_rc = CLE_TIMEOUT;
	else
		resp_rc = le32_to_cpu(resp->code);

	if (resp_rc == CLE_OK)
		sess->confirmed = true;

	if (msg->copts.cb)
		return msg->copts.cb(&msg->copts, resp_rc);

	return 0;
}

int cldc_new_sess(const struct cldc_ops *ops,
		  const struct cldc_call_opts *copts,
		  const void *addr, size_t addr_len,
		  const char *user, const char *secret_key,
		  void *private,
		  struct cldc_session **sess_out)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct timeval tv;

	if (addr_len > sizeof(sess->addr))
		return -EINVAL;
	if (!user || !*user || !secret_key || !*secret_key)
		return -EINVAL;
	if (strlen(user) >= sizeof(sess->user))
		return -EINVAL;
	if (strlen(secret_key) >= sizeof(sess->secret_key))
		return -EINVAL;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return -ENOMEM;

#if 0
	sess->log.verbose = true;
#endif

	sess->private = private;
	sess->ops = ops;
	sess->log.func = ops->errlog ? ops->errlog : cldc_errlog;
	sess->fh = g_array_sized_new(FALSE, TRUE, sizeof(struct cldc_fh), 16);
	strcpy(sess->user, user);
	strcpy(sess->secret_key, secret_key);

	/* create random SID, next_seqid_out */
	__cld_rand64(sess->sid);
	__cld_rand64(&sess->next_seqid_out);

	/* init other session vars */
	memcpy(sess->addr, addr, addr_len);
	sess->addr_len = addr_len;

	/* create NEW-SESS message */
	msg = cldc_new_msg(sess, copts, CMO_NEW_SESS,
			   sizeof(struct cld_msg_hdr));
	if (!msg) {
		sess_free(sess);
		return -ENOMEM;
	}

	msg->cb = new_sess_cb;

	/* save session */
	*sess_out = sess;

	gettimeofday(&tv, NULL);
	sess->expire_time = tv.tv_sec + CLDC_SESS_EXPIRE;

	sess->ops->timer_ctl(sess->private, true, sess_timer, sess,
			     CLDC_MSG_RETRY);

	return sess_send(sess, msg);
}

/*
 * Force-clean the slate in the library. This may leave the server confused.
 */
void cldc_kill_sess(struct cldc_session *sess)
{
	sess->ops->timer_ctl(sess->private, false, NULL, NULL, 0);
	sess_free(sess);
}

static ssize_t generic_end_cb(struct cldc_msg *msg, const void *resp_p,
			      size_t resp_len, bool ok)
{
	const struct cld_msg_resp *resp = resp_p;
	enum cle_err_codes resp_rc = CLE_OK;

	if (!ok)
		resp_rc = CLE_TIMEOUT;
	else
		resp_rc = le32_to_cpu(resp->code);

	if (msg->copts.cb)
		return msg->copts.cb(&msg->copts, resp_rc);

	return 0;
}

int cldc_nop(struct cldc_session *sess, const struct cldc_call_opts *copts)
{
	struct cldc_msg *msg;

	if (!sess->confirmed)
		return -EINVAL;

	/* create NOP message */
	msg = cldc_new_msg(sess, copts, CMO_NOP,
			   sizeof(struct cld_msg_hdr));
	if (!msg)
		return -ENOMEM;

	msg->cb = generic_end_cb;

	return sess_send(sess, msg);
}

int cldc_del(struct cldc_session *sess, const struct cldc_call_opts *copts,
	     const char *pathname)
{
	struct cldc_msg *msg;
	struct cld_msg_del *del;
	void *p;
	size_t plen;

	if (!sess->confirmed)
		return -EINVAL;

	/* first char must be slash */
	if (*pathname != '/')
		return -EINVAL;

	plen = strlen(pathname);
	if (plen > CLD_INODE_NAME_MAX)
		return -EINVAL;

	/* create DEL message */
	msg = cldc_new_msg(sess, copts, CMO_DEL,
			   sizeof(struct cld_msg_del) + strlen(pathname));
	if (!msg)
		return -ENOMEM;

	msg->cb = generic_end_cb;

	/* fill in DEL-specific name_len, name info */
	del = (struct cld_msg_del *) msg->data;
	del->name_len = cpu_to_le16(plen);
	p = del;
	p += sizeof(struct cld_msg_del);
	memcpy(p, pathname, plen);

	return sess_send(sess, msg);
}

static ssize_t open_end_cb(struct cldc_msg *msg, const void *resp_p,
			   size_t resp_len, bool ok)
{
	const struct cld_msg_open_resp *resp = resp_p;
	struct cldc_fh *fh = msg->cb_private;
	enum cle_err_codes resp_rc = CLE_OK;

	if (!ok)
		resp_rc = CLE_TIMEOUT;
	else {
		if (resp_len < sizeof(resp->resp))
			return -1009;
		resp_rc = le32_to_cpu(resp->resp.code);
	}

	if (resp_rc == CLE_OK) {
		if (resp_len < sizeof(*resp))
			return -1010;
		fh->fh_le = resp->fh;
		fh->valid = true;
	}

	if (msg->copts.cb)
		return msg->copts.cb(&msg->copts, resp_rc);

	return 0;
}

int cldc_open(struct cldc_session *sess,
	      const struct cldc_call_opts *copts,
	      const char *pathname, uint32_t open_mode,
	      uint32_t events, struct cldc_fh **fh_out)
{
	struct cldc_msg *msg;
	struct cld_msg_open *open;
	struct cldc_fh fh, *fhtmp;
	void *p;
	size_t plen;
	int fh_idx;

	*fh_out = NULL;

	if (!sess->confirmed)
		return -EINVAL;

	/* first char must be slash */
	if (*pathname != '/')
		return -EINVAL;

	plen = strlen(pathname);
	if (plen > CLD_INODE_NAME_MAX)
		return -EINVAL;

	/* create OPEN message */
	msg = cldc_new_msg(sess, copts, CMO_OPEN,
			   sizeof(struct cld_msg_open) + strlen(pathname));
	if (!msg)
		return -ENOMEM;

	/* add fh to fh table; get pointer to new fh */
	memset(&fh, 0, sizeof(fh));
	fh.sess = sess;
	fh_idx = sess->fh->len;
	g_array_append_val(sess->fh, fh);

	fhtmp = &g_array_index(sess->fh, struct cldc_fh, fh_idx);

	msg->cb = open_end_cb;
	msg->cb_private = fhtmp;

	/* fill in OPEN-specific info */
	open = (struct cld_msg_open *) msg->data;
	open->mode = cpu_to_le32(open_mode);
	open->events = cpu_to_le32(events);
	open->name_len = cpu_to_le16(plen);
	p = open;
	p += sizeof(struct cld_msg_open);
	memcpy(p, pathname, plen);

	*fh_out = fhtmp;

	return sess_send(sess, msg);
}

int cldc_close(struct cldc_fh *fh, const struct cldc_call_opts *copts)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct cld_msg_close *close_msg;

	if (!fh->valid)
		return -EINVAL;

	sess = fh->sess;

	/* create CLOSE message */
	msg = cldc_new_msg(sess, copts, CMO_CLOSE,
			   sizeof(struct cld_msg_close));
	if (!msg)
		return -ENOMEM;

	/* mark FH as invalid from this point forward */
	fh->valid = false;

	msg->cb = generic_end_cb;

	/* fill in CLOSE-specific fh info */
	close_msg = (struct cld_msg_close *) msg->data;
	close_msg->fh = fh->fh_le;

	return sess_send(sess, msg);
}

int cldc_lock(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	      uint32_t lock_flags, bool wait_for_lock)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct cld_msg_lock *lock;

	if (!fh->valid)
		return -EINVAL;

	sess = fh->sess;

	/* create LOCK message */
	msg = cldc_new_msg(sess, copts,
			   wait_for_lock ? CMO_LOCK : CMO_TRYLOCK,
			   sizeof(struct cld_msg_lock));
	if (!msg)
		return -ENOMEM;

	msg->cb = generic_end_cb;

	/* fill in LOCK-specific info */
	lock = (struct cld_msg_lock *) msg->data;
	lock->fh = fh->fh_le;
	lock->flags = cpu_to_le32(lock_flags);

	return sess_send(sess, msg);
}

int cldc_unlock(struct cldc_fh *fh, const struct cldc_call_opts *copts)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct cld_msg_unlock *unlock;

	if (!fh->valid)
		return -EINVAL;

	sess = fh->sess;

	/* create UNLOCK message */
	msg = cldc_new_msg(sess, copts, CMO_UNLOCK,
			   sizeof(struct cld_msg_unlock));
	if (!msg)
		return -ENOMEM;

	msg->cb = generic_end_cb;

	/* fill in UNLOCK-specific info */
	unlock = (struct cld_msg_unlock *) msg->data;
	unlock->fh = fh->fh_le;

	return sess_send(sess, msg);
}

int cldc_put(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	     const void *data, size_t data_len)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct cld_msg_put *put;

	if (!data || !data_len || data_len > CLD_MAX_MSG_SZ)
		return -EINVAL;

	if (!fh->valid)
		return -EINVAL;

	sess = fh->sess;

	/* create PUT message */
	msg = cldc_new_msg(sess, copts, CMO_PUT,
			   sizeof(struct cld_msg_put) + data_len);
	if (!msg)
		return -ENOMEM;

	put = (struct cld_msg_put *) msg->data;
	put->fh = fh->fh_le;
	put->data_size = cpu_to_le32(data_len);

	memcpy((put + 1), data, data_len);

	msg->cb = generic_end_cb;

	sess_send(sess, msg);

	return 0;
}

#undef XC32
#undef XC64
#define XC32(name) \
	o->name = le32_to_cpu(resp->name)
#define XC64(name) \
	o->name = le64_to_cpu(resp->name)

static ssize_t get_end_cb(struct cldc_msg *msg, const void *resp_p,
			  size_t resp_len, bool ok)
{
	const struct cld_msg_get_resp *resp = resp_p;
	enum cle_err_codes resp_rc = CLE_OK;
	struct cld_msg_get_resp *o = NULL;

	if (!ok)
		resp_rc = CLE_TIMEOUT;
	else
		resp_rc = le32_to_cpu(resp->resp.code);

	if (resp_rc == CLE_OK) {
		bool get_body;

		o = &msg->copts.u.get.resp;

		get_body = (resp->resp.hdr.op == CMO_GET);
		msg->copts.op = CMO_GET;

		/* copy-and-swap */
		XC64(inum);
		XC32(ino_len);
		XC32(size);
		XC64(version);
		XC64(time_create);
		XC64(time_modify);
		XC32(flags);

		/* copy inode name */
		if (o->ino_len <= CLD_INODE_NAME_MAX) {
			size_t diffsz;
			const void *p;

			p = (resp + 1);
			memcpy(&msg->copts.u.get.inode_name, p, o->ino_len);

			p += o->ino_len;
			diffsz = p - resp_p;

			/* point to internal buffer holding GET data */
			msg->copts.u.get.buf = msg->sess->msg_buf + diffsz;
			msg->copts.u.get.size = msg->sess->msg_buf_len - diffsz;
		} else {
			o->ino_len = 0;		/* Probably full of garbage */
		}
	}

	if (msg->copts.cb)
		return msg->copts.cb(&msg->copts, resp_rc);
	return 0;
}
#undef XC

int cldc_get(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	     bool metadata_only)
{
	struct cldc_session *sess;
	struct cldc_msg *msg;
	struct cld_msg_get *get;

	if (!fh->valid)
		return -EINVAL;

	sess = fh->sess;

	/* create GET message */
	msg = cldc_new_msg(sess, copts, CMO_GET,
			   sizeof(struct cld_msg_get));
	if (!msg)
		return -ENOMEM;

	msg->cb = get_end_cb;

	/* fill in GET-specific info */
	get = (struct cld_msg_get *) msg->data;
	get->fh = fh->fh_le;

	return sess_send(sess, msg);
}

int cldc_dirent_count(const void *data, size_t data_len)
{
	const void *p = data;
	size_t tmp_len = data_len;
	size_t str_len, rec_len, pad, total_len;
	const uint16_t *tmp16;
	int count = 0;

	while (tmp_len > 0) {
		if (tmp_len < 2)
			return -2;

		tmp16		= p;
		str_len		= le16_to_cpu(*tmp16);
		rec_len		= str_len + 2;
		pad		= CLD_ALIGN8(rec_len);
		total_len	= rec_len + pad;

		if (total_len > tmp_len)
			return -2;

		count++;

		p += total_len;
		tmp_len -= total_len;
	}

	return count;
}

static int dirent_length(const void *buf, size_t buflen, size_t *str_len_out)
{
	size_t str_len, rec_len, pad, total_len;
	const uint16_t *tmp16;

	if (buflen < 2)
		return -1;

	tmp16		= buf;
	str_len		= le16_to_cpu(*tmp16);
	rec_len		= str_len + 2;
	pad		= CLD_ALIGN8(rec_len);
	total_len	= rec_len + pad;

	if (total_len > buflen)
		return -1;

	if (str_len_out)
		*str_len_out = str_len;

	return total_len;
}

int cldc_dirent_first(struct cld_dirent_cur *dc)
{
	int dirent_len;

	dirent_len = dirent_length(dc->p, dc->tmp_len, NULL);
	if (dirent_len < 0)
		return -2;

	return 0;
}

int cldc_dirent_next(struct cld_dirent_cur *dc)
{
	int dirent_len;

	dirent_len = dirent_length(dc->p, dc->tmp_len, NULL);
	if (dirent_len < 0)
		return -2;

	dc->p += dirent_len;
	dc->tmp_len -= dirent_len;

	dirent_len = dirent_length(dc->p, dc->tmp_len, NULL);
	if (dirent_len < 0)
		return -2;

	return 0;
}

void cldc_dirent_cur_init(struct cld_dirent_cur *dc, const void *buf, size_t buflen)
{
	memset(dc, 0, sizeof(*dc));
	dc->p = buf;
	dc->tmp_len = buflen;
}

void cldc_dirent_cur_fini(struct cld_dirent_cur *dc)
{
	/* do nothing */
}

char *cldc_dirent_name(struct cld_dirent_cur *dc)
{
	const uint16_t *tmp16 = dc->p;
	size_t str_len = le16_to_cpu(*tmp16);
	char *s;

	s = malloc(str_len + 1);
	if (!s)
		return NULL;

	memcpy(s, dc->p + 2, str_len);
	s[str_len] = 0;

	return s;
}

/*
 * For extra safety, call cldc_init after g_thread_init, if present.
 * Currently we just call srand(), but since we use GLib, we may need
 * to add some Glib stuff here and that must come after g_thread_init.
 */
void cldc_init()
{
	srand(time(NULL) ^ getpid());	// for __cld_rand64 et.al.
}



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

#include "cld-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <glib.h>
#include <cldc.h>

enum {
	CLDC_MSG_EXPIRE			= 5 * 60,
	CLDC_MSG_SCAN			= 60,
	CLDC_MSG_RETRY			= 5,
};

static time_t cldc_current_time;

int cldcli_init(void)
{
	srand(time(NULL) ^ getpid());

	return 0;
}

void cldcli_free(struct cld_client *cldc)
{
	if (!cldc)
		return;

	if (cldc->fd >= 0)
		close(cldc->fd);
	
	memset(cldc, 0, sizeof(*cldc));
	free(cldc);
}

struct cld_client *cldcli_new(const char *remote_host, int remote_port,
			    int local_port)
{
	struct cld_client *cldc;
	struct addrinfo hints, *res = NULL, *tr;
	int rc;
	char port_str[32];

	sprintf(port_str, "%d", local_port);

	cldc = calloc(1, sizeof(*cldc));
	if (!cldc)
		return NULL;

	cldc->fd = -1;
	cldc->local_port = local_port;
	strncpy(cldc->host, remote_host, sizeof(cldc->host));
	cldc->host[sizeof(cldc->host) - 1] = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, port_str, &hints, &res);
	if (rc)
		goto err_out;

	/* we just use the first successful result, for now */

	for (tr = res; tr != NULL; tr = tr->ai_next) {
		cldc->fd = socket(tr->ai_family, tr->ai_socktype,
				  tr->ai_protocol);
		if (cldc->fd < 0)
			continue;

		if (bind(cldc->fd, tr->ai_addr, tr->ai_addrlen) == 0)
			break;

		close(cldc->fd);
		cldc->fd = -1;
	}

	if (cldc->fd < 0)
		goto err_out_res;

	memcpy(&cldc->local_addr, tr->ai_addr, tr->ai_addrlen);
	cldc->local_addrlen = tr->ai_addrlen;

	freeaddrinfo(res);

	if (fcntl(cldc->fd, F_SETFL, O_NONBLOCK) < 0)
		goto err_out;

	sprintf(port_str, "%d", remote_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	res = NULL;

	rc = getaddrinfo(cldc->host, port_str, &hints, &res);
	if (rc)
		goto err_out;

	memcpy(&cldc->addr, res->ai_addr, res->ai_addrlen);
	cldc->addrlen = res->ai_addrlen;

	freeaddrinfo(res);

	return cldc;

err_out_res:
	freeaddrinfo(res);
err_out:
	free(cldc);
	return NULL;
}

static const struct cld_msg_hdr def_msg_ack = {
	.magic		= CLD_MAGIC,
	.op		= cmo_ack,
};

static int cldc_rx_generic(struct cldc *cldc, struct cldc_session *sess,
			   const struct cld_msg_hdr *msg)
{
	struct cld_msg_hdr resp;
	struct cldc_msg *outmsg = NULL;
	ssize_t rc;
	GList *tmp;

	tmp = sess->out_msg;
	while (tmp) {
		outmsg = tmp->data;
		if (!memcmp(outmsg->msgid, msg->msgid, CLD_MSGID_SZ))
			break;
		tmp = tmp->next;
	}
	if (!tmp)
		return -5;

	if (!outmsg->done) {
		outmsg->done = true;

		if (outmsg->cb) {
			rc = outmsg->cb(outmsg, true);
			if (rc < 0)
				return rc;
		}
	}

	memcpy(&resp, &def_msg_ack, sizeof(resp));
	memcpy(&resp.msgid, msg->msgid, CLD_MSGID_SZ);
	memcpy(&resp.sid, sess->sid, CLD_SID_SZ);

	return cldc->pkt_send(cldc->private, sess->addr, sess->addr_len,
			      &resp, sizeof(resp));
}

static int cldc_rx_end_sess(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen)
{
	return -55;	/* FIXME */
}

static int cldc_rx_open(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen)
{
	return -55;	/* FIXME */
}

static int cldc_rx_data(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen)
{
	return -55;	/* FIXME */
}

static int cldc_rx_event(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen)
{
	return -55;	/* FIXME */
}

static int cldc_rx_not_master(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen)
{
	return -55;	/* FIXME */
}

static int cldc_rx_get(struct cldc *cldc, struct cldc_session *sess,
			   const void *buf, size_t buflen, bool meta_only)
{
	return -55;	/* FIXME */
}

static void sess_expire_outmsg(struct cldc_session *sess)
{
	GList *tmp, *tmp1;

	tmp = sess->out_msg;
	while (tmp) {
		struct cldc_msg *msg;

		tmp1 = tmp;
		tmp = tmp->next;

		msg = tmp1->data;
		if (cldc_current_time > msg->expire_time) {
			free(msg);
			sess->out_msg = g_list_delete_link(sess->out_msg, tmp1);
		}
	}

	sess->msg_scan_time = cldc_current_time + CLDC_MSG_SCAN;
}

int cldc_receive_pkt(struct cldc *cldc,
		     const void *net_addr, size_t net_addrlen,
		     const void *buf, size_t buflen)
{
	const struct cld_msg_hdr *msg = buf;
	struct cldc_session *sess = NULL;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	cldc_current_time = tv.tv_sec;

	if (buflen < sizeof(*msg))
		return -2;
	if (memcmp(msg->magic, CLD_MAGIC, sizeof(msg->magic)))
		return -2;

	/* look up session by sid */
	sess = g_hash_table_lookup(cldc->sessions, msg->sid);
	if (!sess)
		return -2;

	/* verify stored server addr matches pkt addr */
	if (((sess->addr_len != net_addrlen) ||
	    memcmp(sess->addr, net_addr, net_addrlen)))
		return -3;

	/* expire old sess outgoing messages */
	if (cldc_current_time >= sess->msg_scan_time)
		sess_expire_outmsg(sess);

	switch(msg->op) {
	case cmo_nop:
	case cmo_close:
	case cmo_del:
	case cmo_lock:
	case cmo_unlock:
	case cmo_trylock:
	case cmo_ping:
	case cmo_put:
	case cmo_new_sess:
		return cldc_rx_generic(cldc, sess, msg);
	case cmo_end_sess:
		return cldc_rx_end_sess(cldc, sess, buf, buflen);
	case cmo_not_master:
		return cldc_rx_not_master(cldc, sess, buf, buflen);
	case cmo_event:
		return cldc_rx_event(cldc, sess, buf, buflen);
	case cmo_open:
		return cldc_rx_open(cldc, sess, buf, buflen);
	case cmo_get_meta:
		return cldc_rx_get(cldc, sess, buf, buflen, false);
	case cmo_get:
		return cldc_rx_get(cldc, sess, buf, buflen, true);
	case cmo_data:
		return cldc_rx_data(cldc, sess, buf, buflen);
	case cmo_ack:
		return -4;
	}

	return -1;
}

static void sess_next_msgid(struct cldc_session *sess, uint8_t *msgid)
{
	uint64_t msgid64 = GUINT64_TO_LE(sess->next_msgid++);
	memcpy(msgid, &msgid64, CLD_MSGID_SZ);
}

static struct cldc_msg *cldc_new_msg(struct cldc *cldc,
				     struct cldc_session *sess,
				     size_t msg_len)
{
	struct cldc_msg *msg;
	struct cld_msg_hdr *hdr;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	msg = calloc(1, sizeof(*msg) + msg_len);
	if (!msg)
		return NULL;

	msg->sess = sess;
	msg->expire_time = tv.tv_sec + CLDC_MSG_EXPIRE;
	
	sess_next_msgid(sess, msg->msgid);

	msg->data_len = msg_len;

	hdr = (struct cld_msg_hdr *) &msg->data[0];
	memcpy(&hdr->magic, CLD_MAGIC, CLD_MAGIC_SZ);
	memcpy(&hdr->msgid, msg->msgid, CLD_MSGID_SZ);
	memcpy(&hdr->sid, sess->sid, CLD_SID_SZ);

	return msg;
}

static ssize_t new_sess_cb(struct cldc_msg *msg, bool ok)
{
	struct cldc_session *sess = msg->sess;

	if (!ok) {
		/* FIXME: timeout */
		return -1;
	}

	sess->confirmed = true;

	return 0;
}

static void sess_msg_drop(struct cldc_session *sess)
{
	GList *tmp = sess->out_msg;
	struct cldc_msg *msg;

	while (tmp) {
		msg = tmp->data;
		tmp = tmp->next;
		
		if (!msg->done && msg->cb)
			msg->cb(msg, false);

		free(msg);
	}

	g_list_free(sess->out_msg);
	sess->out_msg = NULL;
}

static void sess_expire(struct cldc_session *sess)
{
	struct cldc *cldc = sess->cldc;

	sess->expired = true;
	sess_msg_drop(sess);

	cldc->timer_ctl(cldc->private, false, NULL, 0);

	cldc->event(cldc->private, CLDC_EVT_SESS_FAILED);
}

static int sess_timer(struct cldc *cldc, void *priv)
{
	struct cldc_session *sess = priv;
	struct cldc_msg *msg;
	GList *tmp = sess->out_msg;

	if (cldc_current_time > sess->expire_time) {
		sess_expire(sess);
		return 0;
	}

	while (tmp) {
		msg = tmp->data;
		tmp = tmp->next;

		msg->retries++;
		cldc->pkt_send(cldc->private,
			       sess->addr, sess->addr_len,
			       msg->data, msg->data_len);
	}

	return CLDC_MSG_RETRY;
}

static int sess_send(struct cldc *cldc, struct cldc_session *sess,
		     struct cldc_msg *msg)
{
	sess->out_msg = g_list_append(sess->out_msg, msg);

	if (cldc->pkt_send(cldc->private,
		       sess->addr, sess->addr_len,
		       msg->data, msg->data_len) < 0)
		return -1;

	return 0;
}

int cldc_new_sess(struct cldc *cldc, const void *addr, size_t addr_len,
		  struct cldc_session **sess_out)
{
	struct cldc_session *sess;
	uint32_t v;
	void *p;
	struct cldc_msg *msg;
	struct cld_msg_hdr *hdr;

	if (addr_len > sizeof(sess->addr))
		return -EINVAL;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return -ENOMEM;

	/* create random SID, next_msgid */
	p = &sess->sid;
	v = rand();
	memcpy(p, &v, sizeof(v));
	v = rand();
	memcpy(p + 4, &v, sizeof(v));

	p = &sess->next_msgid;
	v = rand();
	memcpy(p, &v, sizeof(v));
	v = rand();
	memcpy(p + 4, &v, sizeof(v));

	/* init other session vars */
	sess->cldc = cldc;
	memcpy(sess->addr, addr, addr_len);
	sess->addr_len = addr_len;

	/* create NEW-SESS message */
	msg = cldc_new_msg(cldc, sess, sizeof(struct cld_msg_hdr));
	if (!msg) {
		free(sess);
		return -ENOMEM;
	}

	msg->cb = new_sess_cb;

	hdr = (struct cld_msg_hdr *) &msg->data;
	hdr->op = cmo_new_sess;

	/* save session */
	*sess_out = sess;

	g_hash_table_insert(cldc->sessions, sess->sid, sess);

	cldc->timer_ctl(cldc->private, true, sess_timer, CLDC_MSG_RETRY);

	return sess_send(cldc, sess, msg);
}

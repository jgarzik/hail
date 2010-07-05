#ifndef __CLD_H__
#define __CLD_H__

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


#include <netinet/in.h>
#include <sys/time.h>
#include <poll.h>
#include <glib.h>
#include "cldb.h"
#include <cld_msg_rpc.h>
#include <cld_common.h>
#include <hail_log.h>
#include <hail_private.h>

struct client;
struct session_outpkt;

enum {
	CLD_IPADDR_SZ		= 64,
	CLD_SESS_TIMEOUT	= 60,
	CLD_MSGID_EXPIRE	= CLD_SESS_TIMEOUT * 2,
	CLD_RETRY_START		= 2,		/* initial retry after 2sec */
	CLD_CHKPT_SEC		= 60 * 5,	/* secs between db4 chkpt */
	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			addr_host[64];	/* ASCII version of inet addr */
};

struct session {
	uint8_t			sid[CLD_SID_SZ];

	int			sock_fd;

	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			ipaddr[CLD_IPADDR_SZ];

	uint64_t		last_contact;
	uint64_t		next_fh;
	struct cld_timer	timer;

	uint64_t		next_seqid_in;
	uint64_t		next_seqid_out;

	GList			*out_q;		/* outgoing pkts (to client) */
	struct cld_timer	retry_timer;

	char			user[CLD_MAX_USERNAME];

	bool			ping_open;	/* sent PING, waiting for ack */
	bool			dead;		/* session has ended */

	/* huge buffer should always come last */
	enum cld_msg_op		msg_op;
	uint64_t		msg_xid;
	unsigned int		msg_buf_len;
	char			msg_buf[CLD_MAX_MSG_SZ];
};

struct server_stats {
	unsigned long		poll;		/* num. polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		garbage;	/* num. garbage pkts dropped */
};

struct server_poll {
	int			fd;
	bool			(*cb)(int fd, short events, void *userdata);
	void			*userdata;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*data_dir;	/* database/log dir */
	char			*pid_file;	/* PID file */
	int			pid_fd;

	char			*port;		/* bind port, NULL means auto */
	char			*port_file;	/* Port file to write */

	struct cldb		cldb;		/* database info */

	GArray			*polls;
	GArray			*poll_data;

	GHashTable		*sessions;

	struct cld_timer_list	timers;

	struct cld_timer	chkpt_timer;	/* db4 checkpoint timer */

	struct server_stats	stats;		/* global statistics */
};

struct pkt_info {
	struct cld_pkt_hdr	*pkt;
	struct session		*sess;
	uint64_t		seqid;
	uint64_t		xid;
	enum cld_msg_op		op;
	size_t			hdr_len;
};

/* msg.c */
extern int inode_lock_rescan(DB_TXN *txn, cldino_t inum);
extern void msg_get(struct session *sess, const void *v);
extern void msg_open(struct session *sess, const void *v);
extern void msg_put(struct session *sess, const void *v);
extern void msg_close(struct session *sess, const void *v);
extern void msg_del(struct session *sess, const void *v);
extern void msg_unlock(struct session *sess, const void *v);
extern void msg_lock(struct session *sess, const void *v);
extern void msg_ack(struct session *sess, uint64_t seqid);

/* session.c */
extern uint64_t next_seqid_le(uint64_t *seq);
extern guint sess_hash(gconstpointer v);
extern gboolean sess_equal(gconstpointer _a, gconstpointer _b);
extern void msg_new_sess(int sock_fd, const struct client *cli,
			const struct pkt_info *info);
extern void msg_end_sess(struct session *sess, uint64_t xid);
extern struct raw_session *session_new_raw(const struct session *sess);
extern void sessions_free(void);

/** Send a message as part of a session.
 *
 * @param sess		The session
 * @param xdrproc	The XDR function to use to serialize the data
 * @param xdrdata	The message data
 * @param op		The op of the message
 * @param done_cb	The callback to call when the message has been acked
 * @param done_data	The data to give to done_cb
 *
 * @return		true only if the message was sent
 */
extern bool sess_sendmsg(struct session *sess, xdrproc_t xdrproc,
			 const void *xdrdata, enum cld_msg_op op,
			 void (*done_cb)(struct session_outpkt *),
			 void *done_data);

/** Send a generic response message.
 *
 * @param sess		The session
 * @param code		The error code to send
 */
extern void sess_sendresp_generic(struct session *sess,
				  enum cle_err_codes code);

extern int session_dispose(DB_TXN *txn, struct session *sess);
extern int session_remove_locks(DB_TXN *txn, uint8_t *sid, uint64_t fh,
				cldino_t inum, bool *waiter);
extern int sess_load(GHashTable *ss);

/* server.c */
extern struct server cld_srv;
extern struct hail_log srv_log;
extern struct timeval current_time;
extern int udp_tx(int sock_fd, struct sockaddr *, socklen_t,
		  const void *, size_t);
extern const char *user_key(const char *user);

/** Transmit a single packet.
 *
 * This function doesn't provide error-retransmission logic.
 * It can't handle messages that are bigger than a single packet.
 *
 * @param fd		Socket to send the response on
 * @param cli		Client address data
 * @param sid		The session-id to use. Must be of length CLD_SID_SZ
 * @param seqid		The sequence id to use
 * @param xdrproc	The XDR function to use to serialize the data
 * @param xdrdata	The message data
 * @param op		The op of message to send
 *
 * @return		true only on success
 */
extern void simple_sendmsg(int fd, const struct client *cli,
			   uint64_t sid, const char *username, uint64_t seqid,
			   xdrproc_t xdrproc, const void *xdrdata,
			   enum cld_msg_op op);

/* util.c */
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);

#ifndef HAVE_STRNLEN
extern size_t strnlen(const char *s, size_t maxlen);
#endif

#ifndef HAVE_DAEMON
extern int daemon(int nochdir, int noclose);
#endif

#ifndef HAVE_MEMRCHR
extern void *memrchr (const void * s, int c_in, size_t n);
#endif

#ifndef HAVE_MEMMEM
extern void * memmem(const void *b1, size_t len1, const void *b2, size_t len2);
#endif

#endif /* __CLD_H__ */

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
#include <event.h>
#include <glib.h>
#include "cldb.h"
#include "cld_msg.h"

struct client;
struct server_socket;

#define ALIGN8(n) ((8 - ((n) & 7)) & 7)

enum {
	CLD_IPADDR_SZ		= 64,
	CLD_SESS_TIMEOUT	= 60,
	CLD_MSGID_EXPIRE	= CLD_SESS_TIMEOUT * 2,
	CLD_RETRY_START		= 2,		/* initial retry after 2sec */
	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

struct msgid_hist_ent {
	uint8_t		msgid[CLD_MSGID_SZ];		/* message id */
	uint8_t		sid[CLD_SID_SZ];		/* client id */
	time_t		expire_time;
};

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			addr_host[64];	/* ASCII version of inet addr */
};

struct session_outmsg {
	void			*msg;
	size_t			msglen;
	uint64_t		next_retry;
};

struct session {
	uint8_t			sid[CLD_SID_SZ];

	struct server_socket	*sock;

	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			ipaddr[CLD_IPADDR_SZ];

	uint64_t		last_contact;
	uint64_t		next_fh;
	struct event		timer;

	GList			*put_q;		/* queued PUT pkts */
	GList			*data_q;	/* queued data pkts */

	GList			*out_q;		/* outgoing pkts (to client) */
	struct event		retry_timer;

	bool			ping_open;	/* sent PING, waiting for ack */
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
};

struct server_socket {
	int			fd;
	struct event		ev;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*data_dir;	/* database/log dir */
	char			*pid_file;	/* PID file */

	char			*port;		/* bind port */

	struct cldb		cldb;		/* database info */

	GList			*sockets;

	GHashTable		*sessions;

	GQueue			*timers;

	GHashTable		*msgids;
	GQueue			*msgid_q;

	struct server_stats	stats;		/* global statistics */
};

/* msg.c */
extern bool msg_open(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_put(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_data(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_close(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_del(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_unlock(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_lock(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t, bool);
extern bool msg_ack(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t);
extern bool msg_get(struct server_socket *, DB_TXN *,
		 struct session *, uint8_t *, size_t, bool);

/* session.c */
extern guint sess_hash(gconstpointer v);
extern gboolean sess_equal(gconstpointer _a, gconstpointer _b);
extern bool msg_new_sess(struct server_socket *, DB_TXN *,
		 const struct client *, uint8_t *, size_t);
extern struct raw_session *session_new_raw(const struct session *sess);
extern bool sess_sendmsg(struct session *sess, void *msg_, size_t msglen,
		  bool copy_msg);
extern bool sid_sendmsg(const uint8_t *sid, void *msg_, size_t msglen,
		  bool copy_msg);
extern int session_dispose(DB_TXN *txn, struct session *sess);
extern int session_remove_locks(DB_TXN *txn, uint8_t *sid, uint64_t fh,
				cldino_t inum, bool *waiter);

/* server.c */
extern struct server cld_srv;
extern int debugging;
extern time_t current_time;
extern int udp_tx(struct server_socket *, struct sockaddr *, socklen_t,
	    const void *, size_t);
extern void resp_copy(struct cld_msg_hdr *dest, const struct cld_msg_hdr *src);
extern void resp_err(struct server_socket *, struct session *,
		     struct cld_msg_hdr *, enum cle_err_codes);
extern void resp_ok(struct server_socket *, struct session *,
		    struct cld_msg_hdr *);

/* util.c */
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);

#endif /* __CLD_H__ */

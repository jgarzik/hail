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
#include <cld_msg.h>

struct timer;
struct client;
struct server_socket;
struct session_outpkt;

enum {
	CLD_IPADDR_SZ		= 64,
	CLD_SESS_TIMEOUT	= 60,
	CLD_MSGID_EXPIRE	= CLD_SESS_TIMEOUT * 2,
	CLD_RETRY_START		= 2,		/* initial retry after 2sec */
	CLD_CHKPT_SEC		= 60 * 5,	/* secs between db4 chkpt */
	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

struct timer {
	bool			fired;
	void			(*cb)(struct timer *);
	void			*userdata;
	time_t			expires;
};

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			addr_host[64];	/* ASCII version of inet addr */
};

struct session {
	uint8_t			sid[CLD_SID_SZ];

	struct server_socket	*sock;

	struct sockaddr_in6	addr;		/* inet address */
	socklen_t		addr_len;	/* inet address len */
	char			ipaddr[CLD_IPADDR_SZ];

	uint64_t		last_contact;
	uint64_t		next_fh;
	struct timer		timer;

	uint64_t		next_seqid_in;
	uint64_t		next_seqid_out;

	GList			*put_q;		/* queued PUT pkts */
	GList			*data_q;	/* queued data pkts */

	GList			*out_q;		/* outgoing pkts (to client) */
	struct timer		retry_timer;

	char			user[CLD_MAX_USERNAME];

	bool			ping_open;	/* sent PING, waiting for ack */
};

struct msg_params {
	struct server_socket	*sock;
	const struct client	*cli;
	struct session		*sess;

	const struct cld_packet	*pkt;
	const void		*msg;
	size_t			msg_len;
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
};

struct server_socket {
	int			fd;
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

	char			*port;		/* bind port */

	struct cldb		cldb;		/* database info */

	GArray			*polls;
	GArray			*poll_data;

	GHashTable		*sessions;

	GQueue			*timers;

	struct timer		chkpt_timer;	/* db4 checkpoint timer */

	struct server_stats	stats;		/* global statistics */
};

/* msg.c */
extern int inode_lock_rescan(DB_TXN *txn, cldino_t inum);
extern void msg_open(struct msg_params *);
extern void msg_put(struct msg_params *);
extern void msg_data(struct msg_params *);
extern void msg_close(struct msg_params *);
extern void msg_del(struct msg_params *);
extern void msg_unlock(struct msg_params *);
extern void msg_lock(struct msg_params *, bool);
extern void msg_ack(struct msg_params *);
extern void msg_get(struct msg_params *, bool);

/* session.c */
extern uint64_t next_seqid_le(uint64_t *seq);
extern void pkt_init_sess(struct cld_packet *dest, struct session *sess);
extern void pkt_init_pkt(struct cld_packet *dest, const struct cld_packet *src);
extern guint sess_hash(gconstpointer v);
extern gboolean sess_equal(gconstpointer _a, gconstpointer _b);
extern void msg_new_sess(struct msg_params *, const struct client *);
extern void msg_end_sess(struct msg_params *, const struct client *);
extern struct raw_session *session_new_raw(const struct session *sess);
extern bool sess_sendmsg(struct session *sess, const void *msg_, size_t msglen,
		  void (*done_cb)(struct session_outpkt *),
		  void *done_data);
extern int session_dispose(DB_TXN *txn, struct session *sess);
extern int session_remove_locks(DB_TXN *txn, uint8_t *sid, uint64_t fh,
				cldino_t inum, bool *waiter);
extern int sess_load(GHashTable *ss);

/* server.c */
extern const char *opstr(enum cld_msg_ops op);
extern struct server cld_srv;
extern int debugging;
extern struct timeval current_time;
extern int udp_tx(struct server_socket *, struct sockaddr *, socklen_t,
	    const void *, size_t);
extern void resp_copy(struct cld_msg_resp *resp, const struct cld_msg_hdr *src);
extern void resp_err(struct session *sess,
	      const struct cld_msg_hdr *src, enum cle_err_codes errcode);
extern void resp_ok(struct session *sess, const struct cld_msg_hdr *src);
extern bool authsign(struct cld_packet *pkt, size_t pkt_len);
extern void cldlog(int prio, const char *fmt, ...);

/* util.c */
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern void timer_add(struct timer *timer, time_t expires);
extern void timer_del(struct timer *timer);
extern time_t timers_run(void);

static inline void timer_init(struct timer *timer, void (*cb)(struct timer *),
			      void *userdata)
{
	memset(timer, 0, sizeof(*timer));
	timer->cb = cb;
	timer->userdata = userdata;
}

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

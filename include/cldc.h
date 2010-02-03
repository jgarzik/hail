#ifndef __CLDC_H__
#define __CLDC_H__

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

#include <sys/types.h>
#include <stdbool.h>
#include <glib.h>
#include <cld_msg.h>
#include <cld_common.h>
#include <hail_log.h>

struct cldc_session;

/** per-operation application options */
struct cldc_call_opts {
	/* app-owned */
	int		(*cb)(struct cldc_call_opts *, enum cle_err_codes);
	void		*private;

	/* private; lib-owned */
	enum cld_msg_ops op;
	union {
		struct {
			struct cld_msg_get_resp resp;
			const char *buf;
			unsigned int size;
			char inode_name[CLD_INODE_NAME_MAX + 1];
		} get;
	} u;
};

struct cldc_pkt_info {
	int		pkt_len;
	int		retries;

	/* must be at end of struct */
	struct cld_packet pkt;
	uint8_t		data[0];
};

/** an outgoing message, from client to server */
struct cldc_msg {
	uint64_t	xid;

	struct cldc_session *sess;

	ssize_t		(*cb)(struct cldc_msg *, const void *, size_t, bool);
	void		*cb_private;

	struct cldc_call_opts copts;

	bool		done;

	time_t		expire_time;

	int		data_len;
	int		n_pkts;

	struct cldc_pkt_info *pkt_info[CLD_MAX_PKT_MSG];

	/* must be at end of struct */
	uint8_t		data[0];
};

/** an open file handle associated with a session */
struct cldc_fh {
	uint64_t	fh_le;			/* fh id, LE */
	struct cldc_session *sess;
	bool		valid;
};

/** application-supplied facilities */
struct cldc_ops {
	bool		(*timer_ctl)(void *private, bool add,
				     int (*cb)(struct cldc_session *, void *),
				     void *cb_private,
				     time_t secs);
	int		(*pkt_send)(void *private,
				const void *addr, size_t addrlen,
				const void *buf, size_t buflen);
	void		(*event)(void *private, struct cldc_session *,
				 struct cldc_fh *, uint32_t);
	void		(*errlog)(int prio, const char *fmt, ...);
};

/** a single CLD client session */
struct cldc_session {
	uint8_t		sid[CLD_SID_SZ];	/* client id */

	const struct cldc_ops *ops;
	struct		hail_log log;
	void		*private;

	uint8_t		addr[64];		/* server address */
	size_t		addr_len;

	GArray		*fh;			/* file handle table */

	GList		*out_msg;
	time_t		msg_scan_time;

	time_t		expire_time;
	bool		expired;

	uint64_t	next_seqid_in;
	uint64_t	next_seqid_in_tr;
	uint64_t	next_seqid_out;

	char		user[CLD_MAX_USERNAME];
	char		secret_key[CLD_MAX_SECRET_KEY];

	bool		confirmed;

	unsigned int	msg_buf_len;
	char		msg_buf[CLD_MAX_MSG_SZ];
};

/** Information for a single CLD server host */
struct cldc_host {
	unsigned int	prio;
	unsigned int	weight;
	char		*host;
	unsigned short	port;
};

/** A UDP implementation of the CLD client protocol */
struct cldc_udp {
	uint8_t		addr[64];		/* server address */
	size_t		addr_len;

	int		fd;

	struct cldc_session *sess;

	int		(*cb)(struct cldc_session *, void *);
	void		*cb_private;
};

struct cld_dirent_cur {
	const void	*p;
	size_t		tmp_len;
};

/**
 * Packet received from remote host
 *
 * Called by app when a packet is received from a remote host
 * over the network.
 *
 * @param sess Session associated with received packet
 * @param net_addr Opaque network address
 * @param net_addrlen Size of opaque network address
 * @param buf Pointer to data buffer containing packet
 * @param buflen Length of received packet
 * @return Zero for success, non-zero on error
 */
extern int cldc_receive_pkt(struct cldc_session *sess,
		     const void *net_addr, size_t net_addrlen,
		     const void *buf, size_t buflen);

extern void cldc_init(void);
extern int cldc_new_sess(const struct cldc_ops *ops,
		  const struct cldc_call_opts *copts,
		  const void *addr, size_t addr_len,
		  const char *user, const char *secret_key,
		  void *private,
		  struct cldc_session **sess_out);
extern void cldc_kill_sess(struct cldc_session *sess);
extern int cldc_end_sess(struct cldc_session *sess,
				const struct cldc_call_opts *copts);
extern int cldc_nop(struct cldc_session *sess,
		    const struct cldc_call_opts *copts);
extern int cldc_del(struct cldc_session *sess,
		    const struct cldc_call_opts *copts,
		    const char *pathname);
extern int cldc_open(struct cldc_session *sess,
	      const struct cldc_call_opts *copts,
	      const char *pathname, uint32_t open_mode,
	      uint32_t events, struct cldc_fh **fh_out);
extern int cldc_close(struct cldc_fh *fh, const struct cldc_call_opts *copts);
extern int cldc_unlock(struct cldc_fh *fh, const struct cldc_call_opts *copts);
extern int cldc_lock(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	      uint32_t lock_flags, bool wait_for_lock);
extern int cldc_put(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	     const void *data, size_t data_len);
extern int cldc_get(struct cldc_fh *fh, const struct cldc_call_opts *copts,
	     bool metadata_only);
extern int cldc_dirent_count(const void *data, size_t data_len);
extern int cldc_dirent_first(struct cld_dirent_cur *dc);
extern int cldc_dirent_next(struct cld_dirent_cur *dc);
extern void cldc_dirent_cur_init(struct cld_dirent_cur *dc, const void *buf, size_t buflen);
extern void cldc_dirent_cur_fini(struct cld_dirent_cur *dc);
extern char *cldc_dirent_name(struct cld_dirent_cur *dc);

/* cldc-udp */
extern void cldc_udp_free(struct cldc_udp *udp);
extern int cldc_udp_new(const char *hostname, int port,
		 struct cldc_udp **udp_out);
extern int cldc_udp_receive_pkt(struct cldc_udp *udp);
extern int cldc_udp_pkt_send(void *private,
			  const void *addr, size_t addrlen,
			  const void *buf, size_t buflen);

/* cldc-dns */
extern int cldc_getaddr(GList **host_list, const char *thishost,
			struct hail_log *log);
extern int cldc_saveaddr(struct cldc_host *hp,
			 unsigned int priority,
			 unsigned int weight, unsigned int port,
			 unsigned int nlen, const char *name,
			 struct hail_log *log);

static inline bool seqid_after_eq(uint64_t a_, uint64_t b_)
{
	int64_t a = (int64_t) a_;
	int64_t b = (int64_t) b_;

	return a - b >= 0;
}

static inline bool seqid_before_eq(uint64_t a_, uint64_t b_)
{
	return seqid_after_eq(b_, a_);
}

static inline bool seqid_in_range(uint64_t a, uint64_t b, uint64_t c)
{
	return seqid_after_eq(a, b) && seqid_before_eq(a, c);
}

#endif /* __CLDC_H__ */

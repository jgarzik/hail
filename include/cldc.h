#ifndef __CLDC_H__
#define __CLDC_H__

#include <sys/types.h>
#include <stdbool.h>
#include <event.h>
#include <glib.h>
#include <cld_msg.h>

struct cldc;
struct cldc_msg;
struct cldc_session;
struct cldc_call_opts;

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
			char inode_name[CLD_INODE_NAME_MAX];
		} get;
	} u;
};

/** internal per-data stream information */
struct cldc_stream {
	uint64_t	strid_le;	/**< stream id, LE */
	uint32_t	size;		/**< total bytes in stream */
	uint32_t	next_seg;	/**< next segment number expected */
	void		*bufp;		/**< pointer to next input loc */
	uint32_t	size_left;	/**< bytes remaining */
	struct cldc_call_opts copts;	/**< call options */
	char		buf[0];		/**< the raw data stream bytes */
};

/** an outgoing message, from client to server */
struct cldc_msg {
	uint64_t	seqid;

	struct cldc_session *sess;

	ssize_t		(*cb)(struct cldc_msg *, const void *, size_t, bool);
	void		*cb_private;

	struct cldc_call_opts copts;

	bool		done;

	time_t		expire_time;

	int		retries;

	int		data_len;
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
};

/** a single CLD client session */
struct cldc_session {
	uint8_t		sid[CLD_SID_SZ];	/* client id */

	bool		verbose;

	const struct cldc_ops *ops;
	void		*private;

	uint8_t		addr[64];		/* server address */
	size_t		addr_len;

	GArray		*fh;			/* file handle table */

	GList		*out_msg;
	time_t		msg_scan_time;

	GList		*streams;

	time_t		expire_time;
	bool		expired;

	uint64_t	next_seqid_in;
	uint64_t	next_seqid_in_tr;
	uint64_t	next_seqid_out;

	char		user[CLD_MAX_USERNAME];
	char		secret_key[CLD_MAX_SECRET_KEY];

	bool		confirmed;
};

/** A UDP implementation of the CLD client protocol */
struct cldc_udp {
	uint8_t		addr[64];		/* server address */
	size_t		addr_len;

	int		fd;

	struct event	timer_ev;

	struct cldc_session *sess;

	int		(*cb)(struct cldc_session *, void *);
	void		*cb_private;
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

extern int cldc_new_sess(const struct cldc_ops *ops,
		  const struct cldc_call_opts *copts,
		  const void *addr, size_t addr_len,
		  const char *user, const char *secret_key,
		  void *private,
		  struct cldc_session **sess_out);
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

extern void cldc_udp_free(struct cldc_udp *udp);
extern int cldc_udp_new(const char *hostname, int port,
		 struct cldc_udp **udp_out);
extern int cldc_udp_receive_pkt(struct cldc_udp *udp);
extern int cldc_udp_pkt_send(void *private,
			  const void *addr, size_t addrlen,
			  const void *buf, size_t buflen);
extern bool cldc_levent_timer(void *private, bool add,
		       int (*cb)(struct cldc_session *, void *),
		       void *cb_private,
		       time_t secs);

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

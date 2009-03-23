#ifndef __CLDC_H__
#define __CLDC_H__

#include <sys/types.h>
#include <cld_msg.h>

struct cldc;
struct cldc_msg;
struct cldc_session;
struct cldc_call_opts;

struct cldc_call_opts {
	/* app-owned */
	int		(*cb)(struct cldc_call_opts *, enum cle_err_codes);
	void		*private;

	/* private; lib-owned */
	uint8_t		resp_buf[sizeof(struct cld_msg_get_resp) +
				 CLD_INODE_NAME_MAX];
};

struct cldc_stream {
	uint64_t	strid_le;
	uint32_t	size;
	uint32_t	next_seg;
	void		*bufp;
	uint32_t	size_left;
	struct cldc_call_opts copts;
	char		buf[0];
};

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

struct cldc_fh {
	uint64_t	fh_le;			/* fh id, LE */
	struct cldc_session *sess;
	bool		valid;
};

struct cldc_session {
	uint8_t		sid[CLD_SID_SZ];	/* client id */

	struct cldc	*cldc;

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

struct cldc {
	/* public: set by app */
	void		*private;
	bool		(*timer_ctl)(void *private, bool add,
				     int (*cb)(struct cldc *, void *),
				     time_t secs);
	ssize_t		(*pkt_send)(void *private,
				const void *addr, size_t addrlen,
				const void *buf, size_t buflen);
	void		(*event)(void *private, struct cldc_session *,
				 struct cldc_fh *, uint32_t);

	/* private: managed by lib */
	GHashTable	*sessions;
};

extern int cldc_new_sess(struct cldc *cldc, const struct cldc_call_opts *copts,
			 const void *addr, size_t addr_len,
			 const char *user, const char *secret_key,
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

#ifndef __STORAGED_H__
#define __STORAGED_H__

#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <glib.h>
#include <pcre.h>
#include <event.h>
#include <httputil.h>
#include <elist.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
	STORAGED_PGSZ_INODE	= 1024,
	STORAGED_PGSZ_SESSION	= 512,
	STORAGED_PGSZ_LOCK	= 512,

	MAX_COOKIE_LEN		= 128,

	CLI_REQ_BUF_SZ		= 8192,		/* buffer for req + hdrs */
	CLI_DATA_BUF_SZ		= 8192,

	STD_COOKIE_MIN		= 7,
};

enum errcode {
	AccessDenied,
	InternalError,
	InvalidArgument,
	InvalidVolumeName,
	InvalidURI,
	MissingContentLength,
	NoSuchVolume,
	NoSuchKey,
	PreconditionFailed,
	SignatureDoesNotMatch,
};

enum sql_stmt_indices {
	st_begin,
	st_commit,
	st_rollback,
	st_volume_objects,
	st_add_obj,
	st_del_obj,
	st_object,

	st_last = st_object
};

struct client;
struct client_write;
struct server_volume;
struct server_socket;

enum {
	pat_volume_name,
	pat_volume_host,
	pat_volume_path,
	pat_auth,
};

struct compiled_pat {
	const char	*str;
	int		options;
	pcre		*re;
};

typedef bool (*cli_evt_func)(struct client *, unsigned int);
typedef bool (*cli_write_func)(struct client *, struct client_write *, bool);

struct client_write {
	const void		*buf;		/* write buffer */
	int			len;		/* write buffer length */
	cli_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */

	struct list_head	node;
};

/* internal client socket state */
enum client_state {
	evt_read_req,				/* read request line */
	evt_parse_req,				/* parse request line */
	evt_read_hdr,				/* read header line */
	evt_parse_hdr,				/* parse header line */
	evt_http_req,				/* HTTP request fully rx'd */
	evt_http_data_in,			/* HTTP request's content */
	evt_dispose,				/* dispose of client */
	evt_recycle,				/* restart HTTP request parse */
	evt_ssl_accept,				/* SSL cxn negotiation */
};

struct client {
	enum client_state	state;		/* socket state */

	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	struct event		ev;
	struct event		write_ev;

	SSL			*ssl;
	bool			read_want_write;
	bool			write_want_read;

	struct list_head	write_q;	/* list of async writes */
	bool			writing;

	unsigned int		req_used;	/* amount of req_buf in use */
	char			*req_ptr;	/* start of unexamined data */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	char			*out_user;
	SHA_CTX			out_hash;
	long			out_len;
	bool			out_sync;

	struct backend_obj	*out_bo;

	long			in_len;
	struct backend_obj	*in_obj;

	/* we put the big arrays and objects at the end... */

	struct http_req		req;		/* HTTP request */

	char			req_buf[CLI_REQ_BUF_SZ]; /* input buffer */

	char			netbuf[CLI_DATA_BUF_SZ];
};

struct be_fs_obj_hdr {
	char			checksum[128];
	char			owner[128];
};

struct backend_obj {
	struct server_volume	*vol;
	void			*private;
	char			cookie[MAX_COOKIE_LEN + 1];

	uint64_t		size;
	time_t			mtime;
	char			hashstr[50];
};

struct listen_cfg {
	char			*node;
	char			*port;
	bool			encrypt;
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		opt_write;	/* optimistic writes */
};

struct server_volume {
	char			*name;		/* DNS-friendly short name */
	char			*path;		/* pathname for this volume */
};

struct server_socket {
	int			fd;
	bool			encrypt;
	struct event		ev;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*config;	/* master config file */
	char			*data_dir;
	char			*pid_file;	/* PID file */

	GHashTable		*volumes;
	GHashTable		*backends;

	GList			*listeners;
	GList			*sockets;

	struct server_stats	stats;		/* global statistics */
};

/* be-fs.c */
extern char *fs_obj_pathname(struct server_volume *vol, const char *cookie);
extern struct backend_obj *fs_obj_new(struct server_volume *vol, const char *cookie);
extern struct backend_obj *fs_obj_open(struct server_volume *vol,
				       const char *cookie,
				       enum errcode *err_code);
extern ssize_t fs_obj_write(struct backend_obj *bo, const void *ptr, size_t len);
extern ssize_t fs_obj_read(struct backend_obj *bo, void *ptr, size_t len);
extern void fs_obj_free(struct backend_obj *bo);
extern bool fs_obj_write_commit(struct backend_obj *bo, const char *user,
				const char *hashstr, bool sync_data);
extern bool fs_obj_delete(struct server_volume *vol,
			  const char *cookie, enum errcode *err_code);
extern GList *fs_list_objs(struct server_volume *vol);

/* volume.c */
extern bool volume_list(struct client *cli, const char *user, struct server_volume *volume);
extern bool volume_valid(const char *volume);
extern bool service_list(struct client *cli, const char *user);

/* object.c */
extern bool object_del(struct client *cli, const char *user,
			struct server_volume *volume, const char *key);
extern bool object_put(struct client *cli, const char *user,
			struct server_volume *volume, const char *key,
		long content_len, bool expect_cont, bool sync_data);
extern bool object_get(struct client *cli, const char *user,
			struct server_volume *volume,
                       const char *key, bool want_body);
extern bool cli_evt_http_data_in(struct client *cli, unsigned int events);
extern void cli_out_end(struct client *cli);
extern void cli_in_end(struct client *cli);

/* util.c */
extern size_t strlist_len(GList *l);
extern void __strlist_free(GList *l);
extern void strlist_free(GList *l);
extern void req_free(struct http_req *req);
extern int req_hdr_push(struct http_req *req, char *key, char *val);
extern char *req_hdr(struct http_req *req, const char *key);
extern GHashTable *req_query(struct http_req *req);
extern void syslogerr(const char *prefix);
extern void strup(char *s);
extern int write_pid_file(const char *pid_fn);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern char *time2str(char *strbuf, time_t time);
extern void shastr(const unsigned char *digest, char *outstr);
extern void req_sign(struct http_req *req, const char *volume, const char *key,
	      char *b64hmac_out);

extern void read_config(void);

/* server.c */
extern SSL_CTX *ssl_ctx;
extern int debugging;
extern struct server storaged_srv;
extern struct compiled_pat patterns[];
extern bool cli_err(struct client *cli, enum errcode code);
extern bool cli_resp_xml(struct client *cli, int http_status,
			 GList *content);
extern int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data);
extern bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done);
extern bool cli_write_start(struct client *cli);
extern int cli_req_avail(struct client *cli);
extern int cli_poll_mod(struct client *cli);

#endif /* __STORAGED_H__ */

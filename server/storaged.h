#ifndef __STORAGED_H__
#define __STORAGED_H__

#include <sys/epoll.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <glib.h>
#include <pcre.h>
#include <sqlite3.h>
#include <stdbool.h>
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

enum server_poll_type {
	spt_tcp_srv,				/* TCP server */
	spt_tcp_cli,				/* TCP client */
};

struct client;
struct client_write;
struct server_volume;

struct database {
	sqlite3		*sqldb;
	sqlite3_stmt	*prep_stmts[st_last + 1];
};

struct server_poll {
	enum server_poll_type	poll_type;	/* spt_xxx above */
	union {
		void		*ptr;
		struct client	*cli;
	} u;
};

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
};

struct client {
	enum client_state	state;		/* socket state */

	struct sockaddr_in	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	struct server_poll	poll;		/* poll info */
	struct epoll_event	evt;		/* epoll info */

	struct list_head	write_q;	/* list of async writes */

	struct database		*db;

	unsigned int		req_used;	/* amount of req_buf in use */
	char			*req_ptr;	/* start of unexamined data */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	struct server_volume	*out_vol;
	char			*out_user;
	SHA_CTX			out_hash;
	long			out_len;

	struct backend_obj	*out_bo;

	long			in_len;
	struct server_volume	*in_vol;
	struct backend_obj	*in_obj;

	/* we put the big arrays and objects at the end... */

	struct http_req		req;		/* HTTP request */

	char			req_buf[CLI_REQ_BUF_SZ]; /* input buffer */

	char			netbuf[CLI_DATA_BUF_SZ];
};

struct backend_obj {
	struct server_volume	*vol;
	void			*private;
	char			cookie[MAX_COOKIE_LEN + 1];

	uint64_t		size;
	time_t			mtime;
	char			hashstr[50];
};

struct backend_info {
	const char		*name;

	struct backend_obj	* (*obj_new) (struct server_volume *,
					      struct database *);
	struct backend_obj	* (*obj_open) (struct server_volume *,
					       struct database *,
					       const char *,
					       enum errcode *);
	ssize_t			(*obj_read)(struct backend_obj *,
					    void *, size_t);
	ssize_t			(*obj_write)(struct backend_obj *,
					     const void *, size_t);
	bool			(*obj_write_commit)(struct backend_obj *,
						    const char *, const char *);
	bool			(*obj_delete)(struct server_volume *,
					      struct database *,
					      const char *,
					      enum errcode *);
	void			(*obj_free)(struct backend_obj *);
	GList			* (*list_objs)(struct server_volume *,
					       struct database *);
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		max_evt;	/* epoll events max'd out */
	unsigned long		opt_write;	/* optimistic writes */
};

struct server_volume {
	char			*name;		/* DNS-friendly short name */
	char			*path;		/* pathname for this volume */
	struct backend_info	*be;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*config;	/* master config file */
	char			*data_dir;
	char			*pid_file;	/* PID file */

	int			port;		/* bind port */

	int			epoll_fd;	/* epoll descriptor */

	int			tcp_fd;		/* TCP server desc */
	struct server_poll	tcp_poll;	/* poll info */
	struct epoll_event	tcp_evt;	/* epoll info */

	struct database		*db;

	GHashTable		*volumes;
	GHashTable		*backends;

	struct server_stats	stats;		/* global statistics */
};

/* volume.c */
extern bool volume_list(struct client *cli, const char *user, struct server_volume *volume);
extern bool volume_valid(const char *volume);
extern bool service_list(struct client *cli, const char *user);

/* object.c */
extern bool object_del(struct client *cli, const char *user,
			struct server_volume *volume, const char *key);
extern bool object_put(struct client *cli, const char *user,
			struct server_volume *volume,
		long content_len, bool expect_cont);
extern bool object_get(struct client *cli, const char *user,
			struct server_volume *volume,
                       const char *key, bool want_body);
extern bool cli_evt_http_data_in(struct client *cli, unsigned int events);
extern void cli_out_end(struct client *cli);

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

extern bool sql_begin(struct database *);
extern bool sql_commit(struct database *);
extern bool sql_rollback(struct database *);
extern void read_config(void);
extern struct database *db_open(void);
extern void db_close(struct database *db);

/* server.c */
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

/* storage.c */
extern int register_storage(struct backend_info *be);
extern void unregister_storage(struct backend_info *be);

#endif /* __STORAGED_H__ */

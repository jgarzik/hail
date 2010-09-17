#ifndef __CHUNKD_H__
#define __CHUNKD_H__

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

#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <glib.h>
#include <elist.h>
#include <chunk_msg.h>
#include <hail_log.h>
#include <tchdb.h>
#include <cldc.h>	/* for cld_timer */
#include <objcache.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
	CLI_DATA_BUF_SZ		= CHUNK_BLK_SZ,

	CHD_TRASH_MAX		= 1000,

	CLI_MAX_SENDFILE_SZ	= 512 * 1024,
};

struct client;
struct client_write;

typedef bool (*cli_evt_func)(struct client *, unsigned int);
typedef bool (*cli_write_func)(struct client *, struct client_write *, bool);

struct client_write {
	const void		*buf;		/* write buffer */
	uint64_t		len;		/* write buffer length */
	cli_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */
	bool			sendfile;	/* using sendfile? */

	struct list_head	node;
};

/* internal client socket state */
enum client_state {
	evt_read_fixed,				/* read fixed-len rec */
	evt_read_var,				/* read variable-len rec */
	evt_exec_req,				/* execute request */
	evt_data_in,				/* request's content */
	evt_dispose,				/* dispose of client */
	evt_recycle,				/* restart HTTP request parse */
	evt_ssl_accept,				/* SSL cxn negotiation */
};

struct client {
	enum client_state	state;		/* socket state */

	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	char			addr_port[16];	/* ASCII version of port */
	int			fd;		/* socket */

	char			user[CHD_USER_SZ + 1];

	size_t			table_len;
	uint32_t		table_id;

	SSL			*ssl;
	bool			read_want_write;
	bool			write_want_read;
	bool			first_req;

	struct list_head	write_q;	/* list of async writes */
	bool			writing;

	struct chunksrv_req	creq;
	struct chunksrv_req_getpart creq_getpart;
	unsigned int		req_used;	/* amount of req_buf in use */
	void			*req_ptr;	/* start of unexamined data */
	uint16_t		key_len;
	unsigned int		var_len;	/* len of vari len record */
	bool			second_var;	/* inside 2nd vari len rec? */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	char			*out_user;
	SHA_CTX			out_hash;
	uint64_t		out_len;

	struct backend_obj	*out_bo;
	struct objcache_entry	*out_ce;

	uint64_t		in_len;
	struct backend_obj	*in_obj;

	/* we put the big arrays and objects at the end... */

	char			key[CHD_KEY_SZ];
	char			table[CHD_KEY_SZ];
	char			key2[CHD_KEY_SZ];
	char			netbuf[CLI_DATA_BUF_SZ];
	char			netbuf_out[CLI_DATA_BUF_SZ];
};

struct backend_obj {
	void			*private;
	void			*key;
	size_t			key_len;

	uint64_t		size;
	time_t			mtime;
	unsigned char		hash[CHD_CSUM_SZ];
};

enum st_cld {
	ST_CLD_INIT, ST_CLD_ACTIVE
};

struct listen_cfg {
	char			*node;
	char			*port;
	char			*port_file;
	struct list_head	listeners_node;
};

struct geo {
	char			*area;
	char			*zone;		/* Building */
	char			*rack;
};

struct volume_entry {
	unsigned long long	size;		/* obj size */
	time_t			mtime;		/* obj last-mod time */
	void			*key;		/* obj id */
	int			key_len;
	char			*hash;		/* obj SHA1 checksum */
	char			*owner;		/* obj owner username */
};

struct worker_info {
	enum chunk_errcode	err;		/* error returned to pipe */
	struct client		*cli;		/* associated client conn */

	void			(*thr_ev)(struct worker_info *);
	void			(*pipe_ev)(struct worker_info *);
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		opt_write;	/* optimistic writes */
};

struct server_poll {
	short			events;		/* POLL* from poll.h */
	bool			busy;		/* if true, do not poll us */

						/* callback function, data */
	bool			(*cb)(int fd, short events, void *userdata);
	void			*userdata;
};

struct server_socket {
	int			fd;
	const struct listen_cfg	*cfg;
	struct list_head	sockets_node;
};

enum chk_cmd {
	CHK_CMD_EXIT,
	CHK_CMD_RESCAN
};

enum chk_state {
	CHK_ST_OFF,
	CHK_ST_INIT,
	CHK_ST_IDLE,
	CHK_ST_RUNNING,
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */
	GMutex			*bigmutex;

	char			*config;	/* master config file */
	char			*pid_file;	/* PID file */
	int			pid_fd;

	struct list_head	listeners;
	struct list_head	sockets;	/* points into listeners */

	GHashTable		*fd_info;

	GThreadPool		*workers;	/* global thread worker pool */
	int			max_workers;
	int			worker_pipe[2];

	struct list_head	wr_trash;
	unsigned int		trash_sz;

	char			*ourhost;
	char			*vol_path;
	char			*info_path;
	uint32_t		nid;
	struct geo		loc;

	int			chk_pipe[2];
	GList			*chk_users;

	TCHDB			*tbl_master;
	struct objcache		actives;

	struct server_stats	stats;		/* global statistics */
	enum chk_state		chk_state;
	time_t			chk_done;
};

#define MDB_TABLE_ID	"__chunkd_table_id"

extern struct hail_log cldu_hail_log;

/* be-fs.c */
#include <dirent.h>
struct fs_obj_lister {
	DIR *root;
	char *table_path;

	DIR *d;
	char *sub;
};

extern int fs_open(void);
extern void fs_close(void);
extern void fs_free(void);
extern struct backend_obj *fs_obj_new(uint32_t table_id,
				      const void *kbuf, size_t klen,
				      uint64_t data_len,
				      enum chunk_errcode *err_code);
extern struct backend_obj *fs_obj_open(uint32_t table_id, const char *user,
				       const void *kbuf, size_t klen,
				       enum chunk_errcode *err_code);
extern ssize_t fs_obj_write(struct backend_obj *bo, const void *ptr, size_t len);
extern ssize_t fs_obj_read(struct backend_obj *bo, void *ptr, size_t len);
extern int fs_obj_seek(struct backend_obj *bo, uint64_t ofs);
extern void fs_obj_free(struct backend_obj *bo);
extern bool fs_obj_write_commit(struct backend_obj *bo, const char *user,
				unsigned char *md, bool sync_data);
extern bool fs_obj_delete(uint32_t table_id, const char *user,
		          const void *kbuf, size_t klen,
			  enum chunk_errcode *err_code);
extern int fs_obj_disable(const char *fn);
extern ssize_t fs_obj_sendfile(struct backend_obj *bo, int out_fd, size_t len);
extern int fs_list_objs_open(struct fs_obj_lister *t,
			     const char *root_path, uint32_t table_id);
extern int fs_list_objs_next(struct fs_obj_lister *t, char **fnp);
extern void fs_list_objs_close(struct fs_obj_lister *t);
extern int fs_obj_hdr_read(const char *fn, char **owner,
			   unsigned char *hash,
			   void **keyp, size_t *klenp, size_t *csumlenp,
			   unsigned long long *size, time_t *mtime);
extern GList *fs_list_objs(uint32_t table_id, const char *user);
extern bool fs_table_open(const char *user, const void *kbuf, size_t klen,
		   bool tbl_creat, bool excl_creat, uint32_t *table_id,
		   enum chunk_errcode *err_code);
extern int fs_obj_do_sum(const char *fn, unsigned int klen,
			 unsigned int csumlen, unsigned char *md);

/* object.c */
extern bool object_del(struct client *cli);
extern bool object_put(struct client *cli);
extern bool object_get(struct client *cli, bool want_body);
extern bool object_get_part(struct client *cli);
extern bool object_cp(struct client *cli);
extern bool cli_evt_data_in(struct client *cli, unsigned int events);
extern void cli_out_end(struct client *cli);
extern void cli_in_end(struct client *cli);

/* cldu.c */
extern void cld_init(void);
extern void cldu_add_host(const char *host, unsigned int port);
extern int cld_begin(const char *thishost, uint32_t nid, char *infopath,
		     struct geo *locp, void (*cb)(enum st_cld));
extern void cld_end(void);

/* util.c */
extern size_t strlist_len(GList *l);
extern void __strlist_free(GList *l);
extern void strlist_free(GList *l);
extern void syslogerr(const char *prefix);
extern void strup(char *s);
extern int write_pid_file(const char *pid_fn);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern void timer_init(struct cld_timer *timer, const char *name,
		       void (*cb)(struct cld_timer *), void *userdata);
extern void timer_add(struct cld_timer *timer, time_t expires);
extern void timer_del(struct cld_timer *timer);
extern time_t timers_run(void);
extern char *time2str(char *strbuf, time_t time);
extern void hexstr(const unsigned char *buf, size_t buf_len, char *outstr);

/* server.c */
extern SSL_CTX *ssl_ctx;
extern int debugging;
extern struct server chunkd_srv;
extern void applog(int prio, const char *fmt, ...);
extern bool cli_err(struct client *cli, enum chunk_errcode code, bool recycle_ok);
extern int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data);
extern bool cli_wr_sendfile(struct client *, cli_write_func);
extern bool cli_rd_set_poll(struct client *cli, bool readable);
extern void cli_wr_set_poll(struct client *cli, bool writable);
extern bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done);
extern bool cli_write_start(struct client *cli);
extern int cli_req_avail(struct client *cli);
extern int cli_poll_mod(struct client *cli);
extern bool worker_pipe_signal(struct worker_info *wi);
extern bool tcp_cli_event(int fd, short events, void *userdata);
extern void resp_init_req(struct chunksrv_resp *resp,
		   const struct chunksrv_req *req);

/* config.c */
extern void read_config(void);

/* selfcheck.c */
extern int chk_spawn(TCHDB *hdb);

static inline bool use_sendfile(struct client *cli)
{
#if defined(HAVE_SENDFILE) && defined(HAVE_SYS_SENDFILE_H)
	return cli->ssl ? false : true;
#else
	return false;
#endif
}

#ifndef HAVE_STRNLEN
extern size_t strnlen(const char *s, size_t maxlen);
#endif

#ifndef HAVE_DAEMON
extern int daemon(int nochdir, int noclose);
#endif

#endif /* __CHUNKD_H__ */

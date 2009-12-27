
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

#define _GNU_SOURCE
#include "chunkd-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <locale.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <syslog.h>
#include <poll.h>
#include <argp.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <glib.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <elist.h>
#include <chunksrv.h>
#include <cldc.h>
#include <chunk-private.h>
#include "chunkd.h"

#define PROGRAM_NAME PACKAGE

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLI_MAX_WR_IOV		= 32,		/* max iov per writev(2) */

	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

static struct argp_option options[] = {
	{ "config", 'C', "FILE", 0,
	  "Read master configuration from FILE" },
	{ "debug", 'D', NULL, 0,
	  "Enable debug output" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ "strict-free", 1001, NULL, 0,
	  "For memory-checker runs.  When shutting down server, free local "
	  "heap, rather than simply exit(2)ing and letting OS clean up." },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - data storage daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
static bool use_syslog = true;
static bool strict_free = false;
int debugging = 0;
SSL_CTX *ssl_ctx = NULL;
struct timeval current_time;

struct server chunkd_srv = {
	.config			= "/etc/chunkd.conf",
};

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
	[che_Success] =
	{ "che_Success", 200,
	  "che_Success" },

	[che_AccessDenied] =
	{ "che_AccessDenied", 403,
	  "Access denied" },

	[che_InternalError] =
	{ "che_InternalError", 500,
	  "We encountered an internal error. Please try again." },

	[che_InvalidArgument] =
	{ "che_InvalidArgument", 400,
	  "Invalid Argument" },

	[che_InvalidURI] =
	{ "che_InvalidURI", 400,
	  "Could not parse the specified URI" },

	[che_NoSuchKey] =
	{ "che_NoSuchKey", 404,
	  "The resource you requested does not exist" },

	[che_SignatureDoesNotMatch] =
	{ "che_SignatureDoesNotMatch", 403,
	  "The calculated request signature does not match your provided one" },

	[che_InvalidKey] =
	{ "che_InvalidKey", 400,
	  "Invalid key presented" },

	[che_InvalidTable] =
	{ "che_InvalidTable", 400,
	  "Invalid table requested, or table not open" },
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (use_syslog) {
		vsyslog(prio, fmt, ap);
	} else {
		char *f;
		int len;
		int pid;

		pid = getpid() & 0xFFFFFFFF;
		len = sizeof(PROGRAM_NAME "[0123456789]: ") + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, PROGRAM_NAME "[%u]: %s\n", pid, fmt);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
	}
	va_end(ap);
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'C':
		chunkd_srv.config = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'E':
		use_syslog = false;
		break;
	case 'F':
		chunkd_srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		chunkd_srv.pid_file = strdup(arg);
		break;
	case 1001:			/* --strict-free */
		strict_free = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/*
 * Find out own hostname.
 * This is needed for:
 *  - finding the local domain and its SRV records
 * Do this before our state machines start ticking, so we can quit with
 * a meaningful message easily.
 */
static char *get_hostname(void)
{
	enum { hostsz = 64 };
	char hostb[hostsz];
	char *ret;

	if (gethostname(hostb, hostsz-1) < 0) {
		applog(LOG_ERR, "get_hostname: gethostname error (%d): %s",
		       errno, strerror(errno));
		exit(1);
	}
	hostb[hostsz-1] = 0;
	if ((ret = strdup(hostb)) == NULL) {
		applog(LOG_ERR, "get_hostname: no core (%ld)",
		       (long)strlen(hostb));
		exit(1);
	}
	return ret;
}

static void term_signal(int signo)
{
	server_running = false;
}

static void stats_signal(int signo)
{
	dump_stats = true;
}

#define X(stat) \
	applog(LOG_INFO, "STAT %s %lu", #stat, chunkd_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(opt_write);
}

#undef X

static struct server_poll *srv_poll_lookup(int fd)
{
	return g_hash_table_lookup(chunkd_srv.fd_info, GINT_TO_POINTER(fd));
}

bool srv_poll_del(int fd)
{
	return g_hash_table_remove(chunkd_srv.fd_info, GINT_TO_POINTER(fd));
}

static bool srv_poll_mask(int fd, short mask_set, short mask_clear)
{
	struct server_poll *sp;

	sp = srv_poll_lookup(fd);
	if (!sp)
		return false;

	sp->events = (sp->events & ~mask_clear) | mask_set;

	return true;
}

bool srv_poll_ready(int fd)
{
	struct server_poll *sp;

	sp = srv_poll_lookup(fd);
	if (!sp)
		return false;

	sp->busy = false;

	return true;
}

void resp_init_req(struct chunksrv_resp *resp,
		   const struct chunksrv_req *req)
{
	memset(resp, 0, sizeof(*resp));
	memcpy(resp->magic, req->magic, CHD_MAGIC_SZ);
	resp->nonce = req->nonce;
	resp->data_len = req->data_len;
}

static bool cli_write_free(struct client *cli, struct client_write *tmp,
			   bool done)
{
	bool rcb = false;

	/* call callback, clean up struct */
	if (tmp->cb)
		rcb = tmp->cb(cli, tmp, done);
	list_del(&tmp->node);

	if (chunkd_srv.trash_sz < STD_TRASH_MAX) {

		/* recycle struct for future use */
		memset(tmp, 0, sizeof(*tmp));
		INIT_LIST_HEAD(&tmp->node);

		list_add(&tmp->node, &chunkd_srv.wr_trash);
		chunkd_srv.trash_sz++;
	} else
		free(tmp);

	return rcb;
}

static void cli_write_free_all(struct client *cli)
{
	struct client_write *wr, *tmp;

	list_for_each_entry_safe(wr, tmp, &cli->write_q, node) {
		cli_write_free(cli, wr, false);
	}
}

static void cli_free(struct client *cli)
{
	applog(LOG_INFO, "client %s disconnected", cli->addr_host);

	cli_write_free_all(cli);

	cli_out_end(cli);
	cli_in_end(cli);

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (cli->ssl)
			SSL_shutdown(cli->ssl);
		if (!srv_poll_del(cli->fd))
			applog(LOG_ERR, "TCP cli poll del failed");
		if (close(cli->fd) < 0)
			syslogerr("close(2) TCP client socket");
	}

	if (debugging)
		applog(LOG_DEBUG, "client %s ended", cli->addr_host);

	if (cli->ssl)
		SSL_free(cli->ssl);

	free(cli);
}

static struct client *cli_alloc(bool use_ssl)
{
	struct client *cli;

	/* alloc and init client info */
	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return NULL;

	if (use_ssl) {
		cli->ssl = SSL_new(ssl_ctx);
		if (!cli->ssl) {
			applog(LOG_ERR, "SSL_new failed");
			free(cli);
			return NULL;
		}
	}

	cli->state = evt_read_fixed;
	INIT_LIST_HEAD(&cli->write_q);
	cli->req_ptr = &cli->creq;

	return cli;
}

static bool cli_evt_dispose(struct client *cli, unsigned int events)
{
	/* if write queue is not empty, we should continue to get
	 * poll callbacks here until it is
	 */
	if (list_empty(&cli->write_q))
		cli_free(cli);

	return false;
}

static bool cli_evt_recycle(struct client *cli, unsigned int events)
{
	cli->req_ptr = &cli->creq;
	cli->req_used = 0;
	cli->state = evt_read_fixed;

	return true;
}

bool cli_wr_set_poll(struct client *cli, bool writable)
{
	if (writable)
		srv_poll_mask(cli->fd, POLLOUT, 0);
	else
		srv_poll_mask(cli->fd, 0, POLLOUT);

	return true;
}

static int cli_wr_iov(struct client *cli, struct iovec *iov, int max_iov)
{
	struct client_write *tmp;
	int n_iov = 0;

	/* accumulate pending writes into iovec */
	list_for_each_entry(tmp, &cli->write_q, node) {
		if (n_iov >= max_iov)
			break;

		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->len;

		n_iov++;
	}

	return n_iov;
}

static void cli_wr_completed(struct client *cli, ssize_t rc, bool *more_work)
{
	struct client_write *tmp;

	/* iterate through write queue, issuing completions based on
	 * amount of data written
	 */
	while (rc > 0) {
		int sz;

		/* get pointer to first record on list */
		tmp = list_entry(cli->write_q.next, struct client_write, node);

		/* mark data consumed by decreasing tmp->len */
		sz = (tmp->len < rc) ? tmp->len : rc;
		tmp->len -= sz;
		tmp->buf += sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * call callback and clean up
		 */
		if (tmp->len == 0)
			if (cli_write_free(cli, tmp, true))
				*more_work = true;
	}
}

static void cli_writable(struct client *cli)
{
	ssize_t rc;
	bool more_work;
	struct client_write *tmp;

restart:
	more_work = false;

	/* we are guaranteed to have at least one entry in write_q */
	tmp = list_entry(cli->write_q.next, struct client_write, node);

	/* execute non-blocking write */
do_write:
	if (tmp->sendfile) {
		rc = fs_obj_sendfile(cli->in_obj, cli->fd,
				     MIN(cli->in_len, CLI_MAX_SENDFILE_SZ));
		if (rc < 0)
			goto err_out;

		cli->in_len -= rc;
	} else if (cli->ssl) {
		rc = SSL_write(cli->ssl, tmp->buf, tmp->len);
		if (rc <= 0) {
			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ) {
				cli->write_want_read = true;
				return;
			}
			if (rc == SSL_ERROR_WANT_WRITE)
				return;

			goto err_out;
		}
	} else {
		struct iovec iov[CLI_MAX_WR_IOV];
		int n_iov = cli_wr_iov(cli, iov, CLI_MAX_WR_IOV);

		rc = writev(cli->fd, iov, n_iov);
		if (rc < 0) {
			if (errno == EINTR)
				goto do_write;
			if (errno != EAGAIN) {
				cli->state = evt_dispose;
				goto err_out;
			}
			return;
		}
	}

	cli_wr_completed(cli, rc, &more_work);

	if (more_work)
		goto restart;

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cli->write_q)) {
		cli->writing = false;
		if (!cli_wr_set_poll(cli, false))
			goto err_out;
	}

	return;

err_out:
	cli->state = evt_dispose;
	cli_write_free_all(cli);
}

bool cli_write_start(struct client *cli)
{
	if (list_empty(&cli->write_q))
		return true;		/* loop, not poll */

	/* if already writing, nothing further to do */
	if (cli->writing)
		return false;		/* poll wait */

	/* attempt optimistic write, in hopes of avoiding poll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	cli_writable(cli);
	if (list_empty(&cli->write_q)) {
		chunkd_srv.stats.opt_write++;
		return true;		/* loop, not poll */
	}

	if (!cli_wr_set_poll(cli, true))
		return true;		/* loop, not poll */

	cli->writing = true;

	return false;			/* poll wait */
}

int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data)
{
	struct client_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	if (!chunkd_srv.trash_sz) {
		wr = calloc(1, sizeof(struct client_write));
		if (!wr)
			return -ENOMEM;

		INIT_LIST_HEAD(&wr->node);
	} else {
		struct list_head *tmp = chunkd_srv.wr_trash.next;
		wr = list_entry(tmp, struct client_write, node);

		list_del_init(&wr->node);
		chunkd_srv.trash_sz--;
	}

	wr->buf = buf;
	wr->len = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	wr->sendfile = false;

	list_add_tail(&wr->node, &cli->write_q);

	return 0;
}

bool cli_wr_sendfile(struct client *cli, cli_write_func cb)
{
	struct client_write *wr;

	wr = calloc(1, sizeof(struct client_write));
	if (!wr)
		return false;

	wr->len = cli->in_len;
	wr->cb = cb;
	wr->sendfile = true;
	INIT_LIST_HEAD(&wr->node);

	list_add_tail(&wr->node, &cli->write_q);

	return true;
}

static int cli_read_data(struct client *cli, void *buf, size_t buflen)
{
	ssize_t rc;

	if (!buflen)
		return 0;

	/* read into remaining free space in buffer */
do_read:
	if (cli->ssl) {
		rc = SSL_read(cli->ssl, buf, buflen);
		if (rc <= 0) {
			if (rc == 0)
				return -EPIPE;
			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ)
				return 0;
			if (rc == SSL_ERROR_WANT_WRITE) {
				cli->read_want_write = true;
				if (!cli_wr_set_poll(cli, true))
					return -EIO;
				return 0;
			}
			return -EIO;
		}
	} else {
		rc = read(cli->fd, buf, buflen);
		if (rc <= 0) {
			if (rc == 0)
				return -EPIPE;
			if (errno == EINTR)
				goto do_read;
			if (errno == EAGAIN)
				return 0;
			return -errno;
		}
	}

	return rc;
}

bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done)
{
	free(wr->cb_data);

	return false;
}

static int cli_write_list(struct client *cli, GList *list)
{
	int rc = 0;
	GList *tmp;

	tmp = list;
	while (tmp) {
		rc = cli_writeq(cli, tmp->data, strlen(tmp->data),
			        cli_cb_free, tmp->data);
		if (rc)
			goto out;

		tmp->data = NULL;
		tmp = tmp->next;
	}

out:
	__strlist_free(list);
	return rc;
}

bool cli_err(struct client *cli, enum chunk_errcode code, bool recycle_ok)
{
	int rc;
	struct chunksrv_resp *resp = NULL;

	if (code != che_Success)
		applog(LOG_INFO, "client %s error %s",
		       cli->addr_host, err_info[code].code);

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	resp_init_req(resp, &cli->creq);

	resp->resp_code = code;

	if (recycle_ok)
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		return true;
	}

	return cli_write_start(cli);
}

static bool cli_resp_xml(struct client *cli, GList *content)
{
	int rc;
	bool rcb;
	size_t content_len = strlist_len(content);
	struct chunksrv_resp *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	resp_init_req(resp, &cli->creq);

	resp->data_len = cpu_to_le64(content_len);

	cli->state = evt_recycle;

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		cli->state = evt_dispose;
		return true;
	}

	rc = cli_write_list(cli, content);
	if (rc) {
		cli->state = evt_dispose;
		return true;
	}

	rcb = cli_write_start(cli);

	if (cli->state == evt_recycle)
		return true;

	return rcb;
}

static bool volume_list(struct client *cli)
{
	char *s;
	GList *content, *tmpl;
	bool rcb;
	GList *res = NULL;

	res = fs_list_objs(cli->table_id, cli->user);

	s = g_markup_printf_escaped(
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListVolumeResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n",

		 "volume");

	content = g_list_append(NULL, s);

	tmpl = res;
	while (tmpl) {
		char timestr[50], *esc_key;
		struct volume_entry *ve;

		ve = tmpl->data;
		tmpl = tmpl->next;

		/* copy-and-escape key into nul-terminated buffer */
		esc_key = g_markup_escape_text(ve->key, ve->key_len);

		s = g_strdup_printf(
                         "  <Contents>\r\n"
			 "    <Name>%s</Name>\r\n"
                         "    <LastModified>%s</LastModified>\r\n"
                         "    <ETag>%s</ETag>\r\n"
                         "    <Size>%llu</Size>\r\n"
                         "    <Owner>%s</Owner>\r\n"
                         "  </Contents>\r\n",

			 esc_key,
			 time2str(timestr, ve->mtime),
			 ve->hash,
			 ve->size,
			 ve->owner);

		content = g_list_append(content, s);

		free(esc_key);
		free(ve->key);
		free(ve);
	}

	g_list_free(res);

	s = strdup("</ListVolumeResult>\r\n");
	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, content);

	g_list_free(content);

	return rcb;
}

static bool volume_open(struct client *cli)
{
	enum chunk_errcode err = che_Success;

	if (!fs_table_open(cli->user, cli->key, cli->key_len,
			   (cli->creq.flags & CHF_TBL_CREAT),
			   (cli->creq.flags & CHF_TBL_EXCL),
			   &cli->table_id, &err))
		goto out;

	memset(cli->table, 0, sizeof(cli->table));
	memcpy(cli->table, cli->key, cli->key_len);
	cli->table_len = cli->key_len;

out:
	return cli_err(cli, err, true);
}

static bool authcheck(const struct chunksrv_req *req, const void *key,
		      size_t key_len, const char *secret_key)
{
	char req_buf[sizeof(struct chunksrv_req) + CHD_KEY_SZ];
	struct chunksrv_req *tmpreq = (struct chunksrv_req *) req_buf;
	char hmac[64];

	memcpy(tmpreq, req, sizeof(*req));
	memcpy((tmpreq + 1), key, key_len);
	memset(tmpreq->sig, 0, sizeof(tmpreq->sig));

	chreq_sign(tmpreq, secret_key, hmac);

	return strcmp(req->sig, hmac) ? false : true;
}

static bool login_user(struct client *cli)
{
	struct chunksrv_req *req = &cli->creq;
	enum chunk_errcode err;

	/* validate username length */
	if (cli->key_len < 1 || cli->key_len > CHD_USER_SZ) {
		err = che_InvalidArgument;
		cli->state = evt_dispose;
		goto err_out;
	}

	memset(cli->user, 0, sizeof(cli->user));
	memcpy(cli->user, cli->key, cli->key_len);

	/* for lack of a better authentication scheme, we
	 * supply the username as the secret key
	 */
	if (!authcheck(req, cli->key, cli->key_len, cli->user)) {
		err = che_SignatureDoesNotMatch;
		cli->state = evt_dispose;
		goto err_out;
	}

	return cli_err(cli, che_Success, true);

err_out:
	return cli_err(cli, err, false);
}

static bool valid_req_hdr(const struct chunksrv_req *req)
{
	size_t len;

	if (memcmp(req->magic, CHUNKD_MAGIC, CHD_MAGIC_SZ))
		return false;

	len = strnlen(req->sig, sizeof(req->sig));
	if (len < 1 || len == sizeof(req->sig))
		return false;

	return true;
}

static const char *op2str(enum chunksrv_ops op)
{
	switch (op) {
	case CHO_NOP:		return "CHO_NOP";
	case CHO_GET:		return "CHO_GET";
	case CHO_GET_META:	return "CHO_GET_META";
	case CHO_PUT:		return "CHO_PUT";
	case CHO_DEL:		return "CHO_DEL";
	case CHO_LIST:		return "CHO_LIST";
	case CHO_LOGIN:		return "CHO_LOGIN";
	case CHO_TABLE_OPEN:	return "CHO_TABLE_OPEN";

	default:
		return "BUG/UNKNOWN!";
	}

	/* not reached */
	return NULL;
}

static bool cli_evt_exec_req(struct client *cli, unsigned int events)
{
	struct chunksrv_req *req = &cli->creq;
	bool rcb;
	enum chunk_errcode err = che_InvalidArgument;
	bool logged_in = (cli->user[0] != 0);
	bool have_table = (cli->table_len > 0);

	/* validate request header */
	if (!valid_req_hdr(req))
		goto err_out;

	if (debugging)
		applog(LOG_DEBUG, "REQ(op %s, key %s (%u), user %s) "
		       "seq %x len %lld login %s",
		       op2str(req->op),
		       cli->key,
		       cli->key_len,
		       cli->user,
		       req->nonce,
		       (long long) le64_to_cpu(req->data_len),
		       logged_in ? "Y" : "N");

	/* check authentication */
	/* for lack of a better authentication scheme, we
	 * supply the username as the secret key
	 */
	if (logged_in &&
	    !authcheck(req, cli->key, cli->key_len, cli->user)) {
		err = che_SignatureDoesNotMatch;
		goto err_out;
	}

	cli->state = evt_recycle;

	if (G_UNLIKELY((!logged_in) && (req->op != CHO_LOGIN))) {
		cli->state = evt_dispose;
		return true;
	}

	/*
	 * verify open-table requirement, for the operations that need it
	 */
	switch (req->op) {
	case CHO_GET:
	case CHO_GET_META:
	case CHO_PUT:
	case CHO_DEL:
	case CHO_LIST:
		if (!have_table) {
			err = che_InvalidTable;
			goto err_out;
		}
		break;
	default:
		/* do nothing */
		break;
	}

	/*
	 * operations on objects
	 */
	switch (req->op) {
	case CHO_LOGIN:
		if (logged_in)
			goto err_out;
		rcb = login_user(cli);
		break;
	case CHO_NOP:
		rcb = cli_err(cli, che_Success, true);
		break;
	case CHO_GET:
		rcb = object_get(cli, true);
		break;
	case CHO_GET_META:
		rcb = object_get(cli, false);
		break;
	case CHO_PUT:
		rcb = object_put(cli);
		break;
	case CHO_DEL:
		rcb = object_del(cli);
		break;
	case CHO_LIST:
		rcb = volume_list(cli);
		break;
	case CHO_TABLE_OPEN:
		rcb = volume_open(cli);
		break;
	default:
		rcb = cli_err(cli, che_InvalidURI, true);
		break;
	}

out:
	return rcb;

err_out:
	rcb = cli_err(cli, err, false);
	goto out;
}

static bool cli_evt_read_fixed(struct client *cli, unsigned int events)
{
	int rc = cli_read_data(cli, cli->req_ptr,
			       sizeof(cli->creq) - cli->req_used);
	if (rc < 0) {
		cli->state = evt_dispose;
		return true;
	}

	cli->req_ptr += rc;
	cli->req_used += rc;

	/* poll for more, if fixed-length record not yet received */
	if (cli->req_used < sizeof(struct chunksrv_req))
		return false;

	cli->key_len = GUINT16_FROM_LE(cli->creq.key_len);

	/* if no key, skip to execute-request state */
	if (cli->key_len == 0) {
		cli->state = evt_exec_req;
		return true;
	}

	/* drop cxn if invalid key length */
	if (cli->key_len > CHD_KEY_SZ) {
		cli->state = evt_dispose;
		return true;
	}

	/* otherwise, go to read-variable-len-record state */
	cli->req_ptr = &cli->key;
	cli->req_used = 0;
	cli->state = evt_read_var;

	return true;
}

static bool cli_evt_read_var(struct client *cli, unsigned int events)
{
	int rc = cli_read_data(cli, cli->req_ptr,
			       cli->key_len - cli->req_used);
	if (rc < 0) {
		cli->state = evt_dispose;
		return true;
	}

	cli->req_ptr += rc;
	cli->req_used += rc;

	/* poll for more, if variable-length record not yet received */
	if (cli->req_used < cli->key_len)
		return false;

	cli->state = evt_exec_req;

	return true;
}

static bool cli_evt_ssl_accept(struct client *cli, unsigned int events)
{
	int rc;

	rc = SSL_accept(cli->ssl);
	if (rc > 0) {
		cli->state = evt_read_fixed;
		return true;
	}

	rc = SSL_get_error(cli->ssl, rc);

	if (rc == SSL_ERROR_WANT_READ)
		return false;

	if (rc == SSL_ERROR_WANT_WRITE) {
		cli->read_want_write = true;
		if (!cli_wr_set_poll(cli, true))
			goto out;
		return false;
	}

out:
	cli->state = evt_dispose;
	return true;
}

static cli_evt_func state_funcs[] = {
	[evt_read_fixed]	= cli_evt_read_fixed,
	[evt_read_var]		= cli_evt_read_var,
	[evt_exec_req]		= cli_evt_exec_req,
	[evt_data_in]		= cli_evt_data_in,
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
	[evt_ssl_accept]	= cli_evt_ssl_accept,
};

static void tcp_cli_wr_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	if (cli->read_want_write) {
		cli->read_want_write = false;
		if (!cli_wr_set_poll(cli, false))
			cli->state = evt_dispose;
	} else
		cli_writable(cli);
}

static bool tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;
	bool loop = false, disposing = false;

	if (events & POLLOUT)
		tcp_cli_wr_event(fd, events & ~POLLIN, userdata);

	if (cli->write_want_read) {
		cli->write_want_read = false;
		cli_writable(cli);
	} else
		loop = true;

	while (loop) {
		disposing = (cli->state == evt_dispose);
		loop = state_funcs[cli->state](cli, events);
	}

	if (!disposing && !srv_poll_ready(fd))
		applog(LOG_ERR, "unable to ready cli fd for polling");

	return true;	/* continue main loop; do NOT terminate server */
}

static bool tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	int rc, on = 1;
	struct server_poll *sp;

	cli = cli_alloc(sock->cfg->encrypt);
	if (!cli) {
		applog(LOG_ERR, "out of memory");
		return false;	/* end main loop; terminate server */
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	chunkd_srv.stats.tcp_accept++;

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	if (sock->cfg->encrypt) {
		if (!SSL_set_fd(cli->ssl, cli->fd))
			goto err_out_fd;

		rc = SSL_accept(cli->ssl);
		if (rc <= 0) {
			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ)
				cli->state = evt_ssl_accept;
			else if (rc == SSL_ERROR_WANT_WRITE) {
				cli->state = evt_ssl_accept;
				cli->read_want_write = true;
			}
			else {
				unsigned long e = ERR_get_error();
				char estr[121] = "(none?)";

				if (e)
					ERR_error_string(e, estr);
				applog(LOG_WARNING, "%s SSL error %s",
				       cli->addr_host, estr);
				goto err_out_fd;
			}
		}
	}

	sp = calloc(1, sizeof(*sp));
	if (!sp)
		goto err_out_fd;

	sp->fd = cli->fd;
	sp->events = POLLIN;
	sp->cb = tcp_cli_event;
	sp->userdata = cli;

	if (cli->read_want_write) {
		cli->writing = true;
		sp->events |= POLLOUT;
	}

	g_hash_table_insert(chunkd_srv.fd_info, GINT_TO_POINTER(cli->fd), sp);

	/* pretty-print incoming cxn info */
	memset(host, 0, sizeof(host));
	getnameinfo((struct sockaddr *) &cli->addr, addrlen,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	applog(LOG_INFO, "client %s connected%s", host,
		cli->ssl ? " via SSL" : "");

	strcpy(cli->addr_host, host);

	if (!srv_poll_ready(fd))
		applog(LOG_ERR, "unable to ready srv fd for polling");

	return true;	/* continue main loop; do NOT terminate server */

err_out_fd:
err_out:
	cli_free(cli);
	return true;	/* continue main loop; do NOT terminate server */
}

static int net_write_port(const char *port_file, const char *port_str)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s\n", port_str);
	fclose(portf);
	return 0;
}

static int net_open_socket(const struct listen_cfg *cfg,
			   int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_socket *sock;
	int fd, on;
	int rc;
	struct server_poll *sp;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		syslogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		syslogerr("setsockopt(SO_REUSEADDR)");
		rc = -errno;
		goto err_out_fd;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		syslogerr("tcp bind");
		rc = -errno;
		goto err_out_fd;
	}

	if (listen(fd, 100) < 0) {
		syslogerr("tcp listen");
		rc = -errno;
		goto err_out_fd;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc)
		goto err_out_fd;

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		rc = -ENOMEM;
		goto err_out_fd;
	}

	sp = calloc(1, sizeof(*sp));
	if (!sp) {
		free(sock);
		rc = -ENOMEM;
		goto err_out_fd;
	}

	sp->fd = fd;
	sp->events = POLLIN;
	sp->cb = tcp_srv_event;
	sp->userdata = sock;

	g_hash_table_insert(chunkd_srv.fd_info, GINT_TO_POINTER(fd), sp);

	sock->fd = fd;
	sock->cfg = cfg;

	chunkd_srv.sockets = g_list_append(chunkd_srv.sockets, sock);
	return fd;

err_out_fd:
	close(fd);
	return rc;
}

/*
 * This, annoyingly, has to have a side effect: it fills out cfg->port,
 * so that we can later export it into CLD.
 */
static int net_open_any(struct listen_cfg *cfg)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int fd4, fd6;
	socklen_t addr_len;
	unsigned short port;
	int rc;

	port = 0;

	/* Thanks to Linux, IPv6 must be bound first. */
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	memcpy(&addr6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
	fd6 = net_open_socket(cfg,
			      AF_INET6, SOCK_STREAM, 0, sizeof(addr6), &addr6);

	if (fd6 >= 0) {
		addr_len = sizeof(addr6);
		if (getsockname(fd6, &addr6, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr6.sin6_port);
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	/* If IPv6 worked, we must use the same port number for IPv4 */
	if (port)
		addr4.sin_port = port;
	fd4 = net_open_socket(cfg,
			      AF_INET, SOCK_STREAM, 0, sizeof(addr4), &addr4);

	if (!port) {
		if (fd4 < 0)
			return fd4;

		addr_len = sizeof(addr4);
		if (getsockname(fd4, &addr4, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr4.sin_port);
	}

	applog(LOG_INFO, "Listening on auto port %u", port);

	free(cfg->port);
	rc = asprintf(&cfg->port, "%u", port);
	if (rc < 0) {
		applog(LOG_ERR, "OOM");
		return -ENOMEM;
	}

	if (cfg->port_file)
		return net_write_port(cfg->port_file, cfg->port);
	return 0;
}

static int net_open_known(const struct listen_cfg *cfg)
{
	int ipv6_found = 0;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(cfg->node, cfg->port, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(%s:%s) failed: %s",
		       cfg->node ? cfg->node : "*",
		       cfg->port, gai_strerror(rc));
		return -EINVAL;
	}

#ifdef __linux__
	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}
#endif

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(cfg, res->ai_family, res->ai_socktype,
				     res->ai_protocol, 
				     res->ai_addrlen, res->ai_addr);
		if (rc < 0)
			goto err_out;

		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on host %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);

	if (cfg->port_file)
		net_write_port(cfg->port_file, cfg->port);
	return 0;

err_out:
	return rc;
}

static int net_open(struct listen_cfg *cfg)
{
	if (!strcmp(cfg->port, "auto"))
		return net_open_any(cfg);
	else
		return net_open_known(cfg);
}

static void fill_poll_arr(gpointer key, gpointer val, gpointer userdata)
{
	int fd = GPOINTER_TO_INT(key);
	struct server_poll *sp = val;
	GArray *pollers = userdata;
	struct pollfd pfd;

	if (sp->busy)
		return;

	pfd.fd = fd;
	pfd.events = sp->events;
	pfd.revents = 0;

	g_array_append_val(pollers, pfd);
}

static int main_loop(void)
{
	GArray *pollers;
	time_t next_timeout;

	pollers = g_array_sized_new(FALSE, FALSE, sizeof(struct pollfd), 200);
	if (!pollers)
		return 1;

	next_timeout = timers_run();

	while (server_running) {
		struct pollfd *pfd;
		int i, fired, rc;

		/* zero, then refill poll array */
		g_array_set_size(pollers, 0);
		g_hash_table_foreach(chunkd_srv.fd_info, fill_poll_arr,pollers);

		/* poll for fd activity, or next timer event */
		rc = poll(&g_array_index(pollers, struct pollfd, 0),
			  pollers->len,
			  next_timeout ? (next_timeout * 1000) : -1);
		if (rc < 0) {
			syslogerr("poll");
			if (errno != EINTR)
				break;
		}

		gettimeofday(&current_time, NULL);

		/* determine which fd's fired; call their callbacks */
		fired = 0;
		for (i = 0; i < pollers->len; i++) {
			struct server_poll *sp;
			bool runrunrun;

			/* ref pollfd struct */
			pfd = &g_array_index(pollers, struct pollfd, i);

			/* if no events fired, move on to next */
			if (!pfd->revents)
				continue;

			fired++;

			sp = g_hash_table_lookup(chunkd_srv.fd_info,
						GINT_TO_POINTER(pfd->fd));
			if (G_UNLIKELY(!sp)) {
				/* BUG! */
				continue;
			}

			sp->busy = true;

			/* call callback, shutting down server if requested */
			runrunrun = sp->cb(sp->fd, pfd->revents, sp->userdata);
			if (!runrunrun) {
				server_running = false;
				break;
			}

			/* if we reached poll(2) activity count, it is
			 * pointless to continue looping
			 */
			if (fired == rc)
				break;
		}

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}

		next_timeout = timers_run();
	}

	if (strict_free)
		g_array_free(pollers, TRUE);

	return 0;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	GList *tmpl;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	/*
	 * Unfortunately, our initialization order is rather rigid.
	 *
	 * First, parse command line. This way errors in parameters can
	 * be written to stderr, where they belong.
	 */
	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * Next, open syslog. From now on, nothing goes to stderr, and
	 * we minimize (or hopefuly eliminate) opening libraries that
	 * do not have a switcheable diagnostic output.
	 */
	if (use_syslog)
		openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);
	if (debugging)
		applog(LOG_INFO, "Verbose debug output enabled");

	cldu_hail_log.verbose = debugging;

	g_thread_init(NULL);
	SSL_library_init();

	/* init SSL */
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		applog(LOG_ERR, "SSL_CTX_new failed");
		exit(1);
	}

	SSL_CTX_set_mode(ssl_ctx, SSL_CTX_get_mode(ssl_ctx) |
			 SSL_MODE_ENABLE_PARTIAL_WRITE);

	/*
	 * Next, read master configuration. This should be done as
	 * early as possible, so that tunables are available.
	 */
	read_config();
	if (!chunkd_srv.ourhost)
		chunkd_srv.ourhost = get_hostname();
	else if (debugging)
		applog(LOG_INFO, "Forcing local hostname to %s",
		       chunkd_srv.ourhost);

	/*
	 * For example, backgrounding and PID file should be done early
	 * (before we do anything that can conflict with other instance),
	 * but not before read_config().
	 */
	if (!(chunkd_srv.flags & SFL_FOREGROUND) && (daemon(1, !use_syslog) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(chunkd_srv.pid_file);
	if (rc < 0)
		goto err_out;
	chunkd_srv.pid_fd = rc;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	chunkd_srv.fd_info = g_hash_table_new_full(g_direct_hash,
						   g_direct_equal,
						   NULL, free);
	if (!chunkd_srv.fd_info) {
		rc = 1;
		goto err_out_session;
	}

	INIT_LIST_HEAD(&chunkd_srv.wr_trash);
	chunkd_srv.trash_sz = 0;

	if (fs_open()) {
		rc = 1;
		goto err_out_fs;
	}

	if (cld_begin(chunkd_srv.ourhost, chunkd_srv.cell, chunkd_srv.nid,
		      &chunkd_srv.loc, NULL)) {
		rc = 1;
		goto err_out_cld;
	}

	/* set up server networking */
	for (tmpl = chunkd_srv.listeners; tmpl; tmpl = tmpl->next) {
		rc = net_open(tmpl->data);
		if (rc)
			goto err_out_listen;
	}

	applog(LOG_INFO, "initialized");

	rc = main_loop();

	applog(LOG_INFO, "shutting down");

	/* net_close(); */
err_out_listen:
	cld_end();
err_out_cld:
	fs_close();
err_out_fs:
	if (strict_free)
		g_hash_table_destroy(chunkd_srv.fd_info);
err_out_session:
	unlink(chunkd_srv.pid_file);
	close(chunkd_srv.pid_fd);
err_out:
	if (strict_free)
		fs_free();
	closelog();
	return rc;
}


#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <locale.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <syslog.h>
#include <argp.h>
#include <errno.h>
#include <time.h>
#include <pcre.h>
#include <sys/types.h>
#include <glib.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <elist.h>
#include "storaged.h"

#define PROGRAM_NAME PACKAGE

#define MY_ENDPOINT "pretzel.yyz.us"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLI_MAX_WR_IOV		= 32,		/* max iov per writev(2) */

	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

static struct argp_option options[] = {
	{ "config", 'f', "FILE", 0,
	  "Read master configuration from FILE" },
	{ "debug", 'D', NULL, 0,
	  "Enable debug output" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - data storage daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
int debugging = 0;
SSL_CTX *ssl_ctx = NULL;

struct server storaged_srv = {
	.config			= "/spare/tmp/storaged/etc/storaged.conf",
	.pid_file		= "/spare/tmp/storaged/run/storaged.pid",
};

struct compiled_pat patterns[] = {
	[pat_volume_name] =
	{ "^\\w+$", 0, },

	[pat_volume_host] =
	{ "^\\s*(\\w+)\\.(\\w.*)$", 0, },

	[pat_volume_path] =
	{ "^/(\\w+)(.*)$", 0, },

	[pat_auth] =
	{ "^STOR (\\w+):(\\S+)", 0, },
};

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
	[AccessDenied] =
	{ "AccessDenied", 403,
	  "Access denied" },

	[InternalError] =
	{ "InternalError", 500,
	  "We encountered an internal error. Please try again." },

	[InvalidArgument] =
	{ "InvalidArgument", 400,
	  "Invalid Argument" },

	[InvalidVolumeName] =
	{ "InvalidVolumeName", 400,
	  "The specified volume is not valid" },

	[InvalidURI] =
	{ "InvalidURI", 400,
	  "Could not parse the specified URI" },

	[MissingContentLength] =
	{ "MissingContentLength", 411,
	  "You must provide the Content-Length HTTP header" },

	[NoSuchVolume] =
	{ "NoSuchVolume", 404,
	  "The specified volume does not exist" },

	[NoSuchKey] =
	{ "NoSuchKey", 404,
	  "The resource you requested does not exist" },

	[PreconditionFailed] =
	{ "PreconditionFailed", 412,
	  "Precondition failed" },

	[SignatureDoesNotMatch] =
	{ "SignatureDoesNotMatch", 403,
	  "The calculated request signature does not match your provided one" },
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'f':
		storaged_srv.config = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'F':
		storaged_srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		storaged_srv.pid_file = arg;
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

static void term_signal(int signal)
{
	server_running = false;
	event_loopbreak();
}

static void stats_signal(int signal)
{
	dump_stats = true;
	event_loopbreak();
}

#define X(stat) \
	syslog(LOG_INFO, "STAT %s %lu", #stat, storaged_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(opt_write);
}

#undef X

static bool cli_write_free(struct client *cli, struct client_write *tmp,
			   bool done)
{
	bool rcb = false;

	if (tmp->cb)
		rcb = tmp->cb(cli, tmp, done);
	list_del(&tmp->node);
	free(tmp);

	return rcb;
}

static void cli_free(struct client *cli)
{
	struct client_write *wr, *tmp;

	list_for_each_entry_safe(wr, tmp, &cli->write_q, node) {
		cli_write_free(cli, wr, false);
	}

	cli_out_end(cli);
	cli_in_end(cli);

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (cli->ssl)
			SSL_shutdown(cli->ssl);
		if (event_del(&cli->ev) < 0)
			syslog(LOG_WARNING, "TCP client event_del");
		close(cli->fd);
	}

	req_free(&cli->req);

	if (debugging)
		syslog(LOG_DEBUG, "client %s ended", cli->addr_host);

	if (cli->ssl)
		SSL_free(cli->ssl);

	free(cli);
}

static struct client *cli_alloc(bool encrypt)
{
	struct client *cli;

	/* alloc and init client info */
	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return NULL;

	if (encrypt) {
		cli->ssl = SSL_new(ssl_ctx);
		if (!cli->ssl) {
			syslog(LOG_ERR, "SSL_new failed");
			free(cli);
			return NULL;
		}
	}

	cli->state = evt_read_req;
	cli->poll.poll_type = spt_tcp_cli;
	cli->poll.u.cli = cli;
	INIT_LIST_HEAD(&cli->write_q);
	cli->req_ptr = cli->req_buf;
	memset(&cli->req, 0, sizeof(cli->req) - sizeof(cli->req.hdr));

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
	unsigned int slop;

	req_free(&cli->req);

	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	slop = cli_req_avail(cli);
	if (slop) {
		memmove(cli->req_buf, cli->req_ptr, slop);
		cli->req_used = slop;

		cli->state = evt_parse_hdr;
	} else {
		cli->req_used = 0;

		cli->state = evt_read_req;
	}
	cli->req_ptr = cli->req_buf;

	memset(&cli->req, 0, sizeof(cli->req));

	return true;
}

static int SSL_writev(SSL *ssl, const struct iovec *iov, int iovcnt)
{
	int i, bytes = 0;

	for (i = 0; i < iovcnt; i++) {
		int tmp;

		tmp = SSL_write(ssl, iov[i].iov_base, iov[i].iov_len);
		if (tmp > 0) {
			bytes += tmp;

			if (tmp == iov[i].iov_len)
				continue;
			return bytes;
		}
		if (bytes)
			return bytes;

		return -1;
	}

	return bytes;
}

static void cli_writable(struct client *cli)
{
	unsigned int n_iov;
	struct client_write *tmp;
	ssize_t rc;
	struct iovec iov[CLI_MAX_WR_IOV];
	bool more_work;

restart:
	n_iov = 0;
	more_work = false;

	/* accumulate pending writes into iovec */
	list_for_each_entry(tmp, &cli->write_q, node) {
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->len;
		n_iov++;
		if (n_iov == CLI_MAX_WR_IOV)
			break;
	}

	/* execute non-blocking write */
do_write:
	if (cli->ssl) {
		rc = SSL_writev(cli->ssl, iov, n_iov);
		if (rc <= 0) {
			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ) {
				cli->write_want_read = true;
				return;
			}
			if (rc == SSL_ERROR_WANT_WRITE)
				return;
			cli->state = evt_dispose;
			return;
		}
	} else {
		rc = writev(cli->fd, iov, n_iov);
		if (rc < 0) {
			if (errno == EINTR)
				goto do_write;
			if (errno != EAGAIN)
				cli->state = evt_dispose;
			return;
		}
	}

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
				more_work = true;
	}

	if (more_work)
		goto restart;

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cli->write_q)) {
		cli->writing = false;
		if (event_del(&cli->write_ev) < 0)
			cli->state = evt_dispose;
	}
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
		storaged_srv.stats.opt_write++;
		return true;		/* loop, not poll */
	}

	if (event_add(&cli->write_ev, NULL) < 0)
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

	wr = malloc(sizeof(struct client_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->len = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	list_add_tail(&wr->node, &cli->write_q);

	return 0;
}

static int cli_read(struct client *cli)
{
	ssize_t rc;

	/* read into remaining free space in buffer */
do_read:
	if (cli->ssl) {
		rc = SSL_read(cli->ssl, cli->req_buf + cli->req_used,
			      (CLI_REQ_BUF_SZ - 1) - cli->req_used);
		if (rc <= 0) {
			if (rc == 0)
				return -EPIPE;
			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ)
				return 0;
			if (rc == SSL_ERROR_WANT_WRITE) {
				cli->read_want_write = true;
				if (event_add(&cli->write_ev, NULL) < 0)
					return -EIO;
				return 0;
			}
			return -EIO;
		}
	} else {
		rc = read(cli->fd, cli->req_buf + cli->req_used,
		  	  (CLI_REQ_BUF_SZ - 1) - cli->req_used);
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

	cli->req_used += rc;

	/* if buffer is full, assume that data will continue
	 * to be received (by a malicious or broken client),
	 * so stop reading now and return an error.
	 *
	 * Therefore, it can be said that the maximum size of a
	 * request to this HTTP server is CLI_REQ_BUF_SZ-1.
	 */
	if (cli->req_used == CLI_REQ_BUF_SZ)
		return -ENOSPC;

	return 0;
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

bool cli_err(struct client *cli, enum errcode code)
{
	int rc;
	char timestr[50], *hdr = NULL, *content = NULL;

	syslog(LOG_INFO, "client %s error %s",
	       cli->addr_host, err_info[code].code);

	if (asprintf(&content,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<Error>\r\n"
"  <Code>%s</Code>\r\n"
"  <Message>%s</Message>\r\n"
"</Error>\r\n",
		     err_info[code].code,
		     err_info[code].msg) < 0)
		return false;

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Type: application/xml\r\n"
"Content-Length: %zu\r\n"
"Date: %s\r\n"
"Connection: close\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     err_info[code].status,
		     strlen(content),
		     time2str(timestr, time(NULL))) < 0) {
		free(content);
		return false;
	}

	cli->state = evt_dispose;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc)
		return true;
	rc = cli_writeq(cli, content, strlen(content), cli_cb_free, content);
	if (rc)
		return true;

	return cli_write_start(cli);
}

bool cli_resp_xml(struct client *cli, int http_status,
			 GList *content)
{
	int rc;
	char *hdr, timestr[50];
	bool rcb, cxn_close = !cli->req.pipeline;

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Type: application/xml\r\n"
"Content-Length: %zu\r\n"
"Date: %s\r\n"
"%s"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     http_status,
		     strlist_len(content),
		     time2str(timestr, time(NULL)),
		     cxn_close ? "Connection: close\r\n" : "") < 0) {
		__strlist_free(content);
		return false;
	}

	if (cxn_close)
		cli->state = evt_dispose;
	else
		cli->state = evt_recycle;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
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

static bool cli_evt_http_req(struct client *cli, unsigned int events)
{
	int captured[16];
	struct http_req *req = &cli->req;
	char *host, *auth, *content_len_str, *cxn_str;
	char *volume = NULL;
	char *path = NULL;
	char *user = NULL;
	char *key = NULL;
	char *method = req->method;
	bool rcb, pslash, buck_in_path = false;
	bool expect_cont = false;
	bool force_close = false;
	bool sync_data;
	enum errcode err;
	struct server_volume *vol = NULL;

	/* grab useful headers */
	host = req_hdr(req, "host");
	content_len_str = req_hdr(req, "content-length");
	auth = req_hdr(req, "authorization");
	cxn_str = req_hdr(req, "connection");
	sync_data = req_hdr(req, "x-data-sync") ? true : false;
	if (req->major > 1 || req->minor > 0) {
		char *expect = req_hdr(req, "expect");
		if (expect && strcasestr(expect, "100-continue"))
			expect_cont = true;
	}

	if (cxn_str && strcasestr(cxn_str, "close"))
		force_close = true;
	if (http11(req) && !force_close)
		req->pipeline = true;

	if (!host) {
		syslog(LOG_INFO, "%s missing Host header", cli->addr_host);
		return cli_err(cli, InvalidArgument);
	}

	/* attempt to obtain volume name from Host */
	if (pcre_exec(patterns[pat_volume_host].re, NULL,
		      host, strlen(host), 0, 0, captured, 16) == 3) {
		if ((strlen(MY_ENDPOINT) == (captured[5] - captured[4])) &&
		    (!memcmp(MY_ENDPOINT, host + captured[4],
		    	     strlen(MY_ENDPOINT)))) {
			volume = strndup(host + captured[2],
					 captured[3] - captured[2]);
			path = strndup(req->uri.path, req->uri.path_len);
		}
	}

	/* attempt to obtain volume name from URI path */
	if (!volume && pcre_exec(patterns[pat_volume_path].re, NULL,
			   req->uri.path, req->uri.path_len,
			   0, 0, captured, 16) == 3) {
		volume = strndup(req->uri.path + captured[2],
				 captured[3] - captured[2]);
		buck_in_path = true;

		if ((captured[5] - captured[4]) > 0)
			path = strndup(req->uri.path + captured[4],
				       captured[5] - captured[4]);
	}

	if (!path)
		path = strdup("/");
	pslash = (strcmp(path, "/") == 0);
	if ((strlen(path) > 1) && (*path == '/'))
		key = path + 1;

	if (debugging)
		syslog(LOG_DEBUG, "%s: method %s, path '%s', volume '%s'",
		       cli->addr_host, method, path, volume);

	/* parse Authentication header */
	if (auth) {
		char b64sig[64];
		int usiglen, rc;

		if (pcre_exec(patterns[pat_auth].re, NULL,
			      auth, strlen(auth), 0, 0,
			      captured, 16) != 3) {
			syslog(LOG_INFO, "%s: Authorization header parse fail",
			       cli->addr_host);
			err = InvalidArgument;
			goto err_out;
		}

		user = strndup(auth + captured[2], captured[3] - captured[2]);
		usiglen = captured[5] - captured[4];

		req_sign(&cli->req, buck_in_path ? NULL : volume, user, b64sig);

		rc = strncmp(b64sig, auth + captured[4], usiglen);

		if (rc) {
			err = SignatureDoesNotMatch;
			goto err_out;
		}
	}

	if (!auth) {
		err = AccessDenied;
		goto err_out;
	}

	if (volume)
		vol = g_hash_table_lookup(storaged_srv.volumes, volume);

	/* no matter whether error or not, this is our next state.
	 * the main question is whether or not we will go immediately
	 * into it (return true) or wait for writes to complete (return
	 * false).
	 *
	 * the operations below may override this next-state setting,
	 * however.
	 */
	if (req->pipeline)
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	/*
	 * pre-operation checks
	 */

	if (volume && !volume_valid(volume))
		rcb = cli_err(cli, InvalidVolumeName);

	/*
	 * operations on objects
	 */
	else if (volume && !pslash && !strcmp(method, "HEAD"))
		rcb = object_get(cli, user, vol, key, false);
	else if (volume && !pslash && !strcmp(method, "GET"))
		rcb = object_get(cli, user, vol, key, true);
	else if (volume && pslash && !strcmp(method, "PUT")) {
		long content_len;

		if (!content_len_str) {
			err = MissingContentLength;
			goto err_out;
		}

		content_len = atol(content_len_str);

		rcb = object_put(cli, user, vol, content_len, expect_cont,
				 sync_data);
	} else if (volume && !pslash && !strcmp(method, "DELETE"))
		rcb = object_del(cli, user, vol, key);

	/*
	 * operations on volumes
	 */
	else if (volume && pslash && !strcmp(method, "GET")) {
		rcb = volume_list(cli, user, vol);
	}

	/*
	 * service-wide operations
	 */
	else if (!volume && pslash && !strcmp(method, "GET")) {
		rcb = service_list(cli, user);
	}

	else
		rcb = cli_err(cli, InvalidURI);

out:
	free(volume);
	free(path);
	free(user);
	return rcb;

err_out:
	rcb = cli_err(cli, err);
	goto out;
}

int cli_req_avail(struct client *cli)
{
	int skip_len = cli->req_ptr - cli->req_buf;
	int search_len = cli->req_used - skip_len;

	return search_len;
}

static char *cli_req_eol(struct client *cli)
{
	/* find newline in unconsumed portion of buffer */
	return memchr(cli->req_ptr, '\n', cli_req_avail(cli));
}

static char *cli_req_line(struct client *cli)
{
	/* get start and end of line */
	char *buf_start = cli->req_ptr;
	char *buf_eol = cli_req_eol(cli);
	if (!buf_eol)
		return NULL;

	/* nul-terminate line, if found */
	*buf_eol = 0;
	cli->req_ptr = buf_eol + 1;

	/* chomp CR, if present */
	if (buf_eol != buf_start) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r')
			*buf_cr = 0;
	}

	/* return saved start-of-line */
	return buf_start;
}

static bool cli_hdr_flush(struct client *cli, bool *loop_state)
{
	char *tmp;
	enum errcode err_resp;

	if (!cli->hdr_start)
		return false;

	/* null terminate entire string (key+value) */
	*cli->hdr_end = 0;

	/* find end of key; ensure no whitespace in key */
	tmp = cli->hdr_start;
	while (*tmp) {
		if (isspace(*tmp)) {
			syslog(LOG_WARNING, "whitespace in header key");
			err_resp = InvalidArgument;
			goto err_out;
		}
		if (*tmp == ':')
			break;
		tmp++;
	}
	if (*tmp != ':') {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* null terminate key */
	*tmp = 0;

	/* add to list of headers */
	if (req_hdr_push(&cli->req, cli->hdr_start, tmp + 1)) {
		syslog(LOG_WARNING, "cannot add to list of headers");
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* reset accumulation state */
	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	return false;

err_out:
	*loop_state = cli_err(cli, err_resp);
	return true;
}

static bool cli_evt_parse_hdr(struct client *cli, unsigned int events)
{
	char *buf, *buf_eol;
	bool eoh = false;

	/* get pointer to end-of-line */
	buf_eol = cli_req_eol(cli);
	if (!buf_eol) {
		cli->state = evt_read_hdr;
		return false;
	}

	/* mark data as consumed */
	buf = cli->req_ptr;
	cli->req_ptr = buf_eol + 1;

	/* convert newline into spaces, for continued header lines */
	*buf_eol = ' ';

	/* chomp CR, if present */
	if (buf_eol != buf) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r') {
			*buf_cr = ' ';
			buf_eol--;
		}
	}

	/* if beginning of line and buf_eol (beginning of \r\n) are
	 * the same, its a blank line, signalling end of headers
	 */
	if (buf == buf_eol)
		eoh = true;

	/* check need to flush accumulated header data */
	if (eoh || (!isspace(buf[0]))) {
		bool sent_resp, loop;

		sent_resp = cli_hdr_flush(cli, &loop);
		if (sent_resp)
			return loop;
	}

	/* if we have reached end of headers, deliver HTTP request */
	if (eoh) {
		cli->state = evt_http_req;
		return true;
	}

	/* otherwise, continue accumulating header data */
	if (!cli->hdr_start)
		cli->hdr_start = buf;
	cli->hdr_end = buf_eol;

	return true;
}

static bool cli_evt_read_hdr(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc < 0) {
		if (rc == -ENOSPC) {
			syslog(LOG_WARNING, "too much invalid header data");
			return cli_err(cli, InvalidArgument);
		}

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_hdr;

	return true;
}

static bool cli_evt_parse_req(struct client *cli, unsigned int events)
{
	char *sp1, *sp2, *buf;
	enum errcode err_resp;
	int len;

	/* get pointer to nul-terminated line received */
	buf = cli_req_line(cli);
	if (!buf) {
		cli->state = evt_read_req;
		return false;
	}

	len = strlen(buf);

	/* locate the first and second spaces, additionally ensuring
	 * that the first and second tokens are non-empty
	 */
	if (*buf == ' ') {
		syslog(LOG_WARNING, "parse req 1 failed");
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp1 = strchr(buf, ' ');
	if ((!sp1) || (*(sp1 + 1) == ' ')) {
		syslog(LOG_WARNING, "parse req 2 failed");
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2) {
		syslog(LOG_WARNING, "parse req 3 failed");
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* convert the two spaces to nuls, thereby creating three
	 * nul-terminated strings for the three pieces we desire
	 */
	*sp1 = 0;
	*sp2 = 0;

	/* method is the first token, at the beginning of the buffer */
	cli->req.method = buf;
	strup(cli->req.method);

	/* URI is the second token, immediately following the first space */
	if (!uri_parse(&cli->req.uri, sp1 + 1)) {
		err_resp = InvalidURI;
		goto err_out;
	}

	cli->req.orig_path = strndup(cli->req.uri.path, cli->req.uri.path_len);

	cli->req.uri.path_len = field_unescape(cli->req.uri.path,
					       cli->req.uri.path_len);

	/* HTTP version is the final token, following second space */
	if ((sscanf(sp2 + 1, "HTTP/%d.%d", &cli->req.major, &cli->req.minor) != 2) ||
	    (cli->req.major != 1) || (cli->req.minor < 0) || (cli->req.minor > 1)) {
		syslog(LOG_INFO, "%s: invalid HTTP version", cli->addr_host);
		err_resp = InvalidArgument;
		goto err_out;
	}

	cli->state = evt_parse_hdr;
	return true;

err_out:
	return cli_err(cli, err_resp);
}

static bool cli_evt_read_req(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc < 0) {
		if (rc == -ENOSPC) {
			syslog(LOG_WARNING, "too much invalid header data 1");
			return cli_err(cli, InvalidArgument);
		}

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_req;

	return true;
}

static bool cli_evt_ssl_accept(struct client *cli, unsigned int events)
{
	int rc;

	rc = SSL_accept(cli->ssl);
	if (rc > 0) {
		cli->state = evt_read_req;
		return true;
	}

	rc = SSL_get_error(cli->ssl, rc);

	if (rc == SSL_ERROR_WANT_READ)
		return false;

	if (rc == SSL_ERROR_WANT_WRITE) {
		cli->read_want_write = true;
		if (event_add(&cli->write_ev, NULL) < 0)
			goto out;
		return false;
	}

out:
	cli->state = evt_dispose;
	return true;
}

static cli_evt_func state_funcs[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= cli_evt_http_req,
	[evt_http_data_in]	= cli_evt_http_data_in,
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
	[evt_ssl_accept]	= cli_evt_ssl_accept,
};

static void tcp_cli_wr_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	if (cli->read_want_write) {
		cli->read_want_write = false;
		if (event_del(&cli->write_ev) < 0)
			cli->state = evt_dispose;
	} else
		cli_writable(cli);
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;
	bool loop = false;

	if (events & EV_READ) {
		if (cli->write_want_read) {
			cli->write_want_read = false;
			cli_writable(cli);
		} else
			loop = true;
	}

	while (loop) {
		loop = state_funcs[cli->state](cli, events);
	}
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	int rc;

	cli = cli_alloc(sock->encrypt);
	if (!cli) {
		syslog(LOG_ERR, "out of memory");
		return;
	}

	cli->db = storaged_srv.db;

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	storaged_srv.stats.tcp_accept++;

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	if (sock->encrypt) {
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
				syslog(LOG_WARNING, "%s SSL error %s",
				       cli->addr_host, estr);
				goto err_out_fd;
			}
		}
	}

	event_set(&cli->ev, cli->fd, EV_READ | EV_PERSIST, tcp_cli_event, cli);
	event_set(&cli->write_ev, cli->fd, EV_WRITE | EV_PERSIST,
		  tcp_cli_wr_event, cli);

	/* add to poll watchlist */
	if (event_add(&cli->ev, NULL) < 0) {
		syslog(LOG_WARNING, "tcp client event_add");
		goto err_out_fd;
	}

	if (cli->read_want_write) {
		cli->writing = true;
		if (event_add(&cli->write_ev, NULL) < 0) {
			syslog(LOG_WARNING, "tcp client event_add 2");
			goto err_out_fd;
		}
	}

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, sizeof(struct sockaddr_in6),
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	syslog(LOG_INFO, "client %s connected%s", host,
		cli->ssl ? " via SSL" : "");

	strcpy(cli->addr_host, host);

	return;

err_out_fd:
err_out:
	cli_free(cli);
}

static int net_open(const struct listen_cfg *cfg)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(cfg->node, cfg->port, &hints, &res0);
	if (rc) {
		syslog(LOG_ERR, "getaddrinfo(%s:%s) failed: %s",
		       cfg->node ? cfg->node : "*",
		       cfg->port, gai_strerror(rc));
		return -EINVAL;
	}

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
	ipv6_found = 0;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}

	for (res = res0; res; res = res->ai_next) {
		struct server_socket *sock;
		int fd, on;

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			syslogerr("tcp socket");
			return -errno;
		}

		on = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
			       sizeof(on)) < 0) {
			syslogerr("setsockopt(SO_REUSEADDR)");
			rc = -errno;
			goto err_out;
		}

		if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
			/* sigh... */
			if (errno == EADDRINUSE && res->ai_family == PF_INET) {
				if (debugging)
					syslog(LOG_INFO, "already bound to socket, ignoring");
				close(fd);
				continue;
			}

			syslogerr("tcp bind");
			rc = -errno;
			goto err_out;
		}

		if (listen(fd, 100) < 0) {
			syslogerr("tcp listen");
			rc = -errno;
			goto err_out;
		}

		rc = fsetflags("tcp server", fd, O_NONBLOCK);
		if (rc)
			goto err_out;

		sock = calloc(1, sizeof(*sock));
		if (!sock) {
			rc = -ENOMEM;
			goto err_out;
		}

		sock->fd = fd;
		sock->encrypt = cfg->encrypt;
		sock->poll.poll_type = spt_tcp_srv;
		sock->poll.u.sock = sock;

		event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
			  tcp_srv_event, sock);

		if (event_add(&sock->ev, NULL) < 0) {
			syslog(LOG_WARNING, "tcp socket event_add");
			rc = -EIO;
			goto err_out;
		}

		storaged_srv.sockets =
			g_list_append(storaged_srv.sockets, sock);
	}

	freeaddrinfo(res0);

	return 0;

err_out:
	return rc;
}

static void compile_patterns(void)
{
	int i;
	const char *error = NULL;
	int erroffset = -1;
	pcre *re;

	for (i = 0; i < ARRAY_SIZE(patterns); i++) {
		re = pcre_compile(patterns[i].str, patterns[i].options,
				  &error, &erroffset, NULL);
		if (!re) {
			syslog(LOG_ERR, "BUG: pattern compile %d failed", i);
			exit(1);
		}

		patterns[i].re = re;
	}
}

static void register_backends(void)
{
	extern int be_fs_init(void);

	int rc;

	rc = be_fs_init();
	if (rc) {
		syslog(LOG_ERR, "'fs' backend init failed");
		exit(1);
	}
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	GList *tmpl;

	srand(time(NULL));

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * open syslog, background outselves, write PID file ASAP
	 */

	openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);

	if (debugging)
		syslog(LOG_INFO, "Verbose debug output enabled");

	g_thread_init(NULL);
	SSL_library_init();

	compile_patterns();

	register_backends();

	/* init SSL */
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		syslog(LOG_ERR, "SSL_CTX_new failed");
		exit(1);
	}

	SSL_CTX_set_mode(ssl_ctx, SSL_CTX_get_mode(ssl_ctx) |
			 SSL_MODE_ENABLE_PARTIAL_WRITE);

	/*
	 * read master configuration
	 */
	read_config();

	if ((!(storaged_srv.flags & SFL_FOREGROUND)) && (daemon(1, 0) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(storaged_srv.pid_file);
	if (rc < 0)
		goto err_out;

	/*
	 * properly capture TERM and other signals
	 */

	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	event_init();

	storaged_srv.db = db_open();
	if (!storaged_srv.db)
		exit(1);

	/* set up server networking */
	tmpl = storaged_srv.listeners;
	while (tmpl) {
		rc = net_open(tmpl->data);
		if (rc)
			goto err_out_pid;

		tmpl = tmpl->next;
	}

	syslog(LOG_INFO, "initialized");

	while (server_running) {
		event_dispatch();

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
	}

	syslog(LOG_INFO, "shutting down");

	db_close(storaged_srv.db);

	rc = 0;

err_out_pid:
	unlink(storaged_srv.pid_file);
err_out:
	closelog();
	return rc;
}


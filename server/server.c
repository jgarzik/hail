#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
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
#include <sys/types.h>
#include <glib.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <elist.h>
#include "chunkd.h"

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

struct server chunkd_srv = {
	.config			= "/spare/tmp/chunkd/etc/chunkd.conf",
	.pid_file		= "/spare/tmp/chunkd/run/chunkd.pid",
};

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
	[Success] =
	{ "Success", 200,
	  "Success" },

	[AccessDenied] =
	{ "AccessDenied", 403,
	  "Access denied" },

	[InternalError] =
	{ "InternalError", 500,
	  "We encountered an internal error. Please try again." },

	[InvalidArgument] =
	{ "InvalidArgument", 400,
	  "Invalid Argument" },

	[InvalidURI] =
	{ "InvalidURI", 400,
	  "Could not parse the specified URI" },

	[MissingContentLength] =
	{ "MissingContentLength", 411,
	  "You must provide the Content-Length HTTP header" },

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
		chunkd_srv.config = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'F':
		chunkd_srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		chunkd_srv.pid_file = arg;
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
	syslog(LOG_INFO, "STAT %s %lu", #stat, chunkd_srv.stats.stat)

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
	cli->state = evt_read_req;

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
		chunkd_srv.stats.opt_write++;
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

	list_add_tail(&wr->node, &cli->write_q);

	return 0;
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
				if (event_add(&cli->write_ev, NULL) < 0)
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

bool cli_err(struct client *cli, enum errcode code)
{
	int rc;
	struct chunksrv_req *resp = NULL;

	syslog(LOG_INFO, "client %s error %s",
	       cli->addr_host, err_info[code].code);

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	memcpy(resp, &cli->creq, sizeof(cli->creq));

	resp->resp_code = code;

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
	int content_len = strlist_len(content);
	struct chunksrv_req *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	memcpy(resp, &cli->creq, sizeof(cli->creq));

	resp->data_len = GUINT64_TO_LE(content_len);

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
	const char *user = cli->creq.user;
	enum errcode err = InternalError;
	char *s;
	GList *content, *tmpl;
	bool rcb;
	GList *res = NULL;

	/* verify READ access */
	if (!user) {
		err = AccessDenied;
		goto err_out;
	}

	res = fs_list_objs();

	asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListVolumeResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n",

		 "volume");

	content = g_list_append(NULL, s);

	tmpl = res;
	while (tmpl) {
		char *hash;
		char *fn, *name, timestr[50];
		struct stat st;

		name = tmpl->data;
		tmpl = tmpl->next;

		hash = tmpl->data;
		tmpl = tmpl->next;

		fn = fs_obj_pathname(name);
		if (!fn)
			goto do_next;

		if (stat(fn, &st) < 0) {
			syslog(LOG_ERR, "blist stat(%s) failed: %s",
				fn, strerror(errno));
			st.st_mtime = 0;
			st.st_size = 0;
		} else
			st.st_size -= sizeof(struct be_fs_obj_hdr);

		asprintf(&s,
                         "  <Contents>\r\n"
			 "    <Name>%s</Name>\r\n"
                         "    <LastModified>%s</LastModified>\r\n"
                         "    <ETag>%s</ETag>\r\n"
                         "    <Size>%llu</Size>\r\n"
                         "    <Owner>%s</Owner>\r\n"
                         "  </Contents>\r\n",

			 name,
			 time2str(timestr, st.st_mtime),
			 hash,
			 (unsigned long long) st.st_size,
			 user);

		content = g_list_append(content, s);

do_next:
		free(name);
		free(hash);
		free(fn);
	}

	g_list_free(res);

	s = strdup("</ListVolumeResult>\r\n");
	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, content);

	g_list_free(content);

	return rcb;

err_out:
	return cli_err(cli, err);
}

static bool valid_req_hdr(const struct chunksrv_req *req)
{
	if (memcmp(req->magic, CHUNKD_MAGIC, CHD_MAGIC_SZ))
		return false;
	if (strnlen(req->user, sizeof(req->user)) == sizeof(req->user))
		return false;
	if (strnlen(req->key, sizeof(req->key)) == sizeof(req->key))
		return false;

	return true;
}

static bool cli_evt_exec_req(struct client *cli, unsigned int events)
{
	struct chunksrv_req *req = &cli->creq;
	bool rcb;
	enum errcode err = InternalError;

	/* validate request header */
	if (!valid_req_hdr(req))
		goto err_out;

	cli->state = evt_recycle;

	/*
	 * operations on objects
	 */
	switch (req->op) {
	case CHO_NOP:
		err = Success;
		goto err_out;
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
	default:
		rcb = cli_err(cli, InvalidURI);
		break;
	}

out:
	return rcb;

err_out:
	rcb = cli_err(cli, err);
	goto out;
}

static bool cli_evt_read_req(struct client *cli, unsigned int events)
{
	int rc = cli_read_data(cli, cli->req_ptr,
			       sizeof(cli->creq) - cli->req_used);
	if (rc < 0) {
		cli->state = evt_dispose;
		return true;
	}
	
	cli->req_ptr += rc;
	cli->req_used += rc;

	if (cli->req_used < sizeof(cli->creq))
		return false;

	cli->state = evt_exec_req;

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

		event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
			  tcp_srv_event, sock);

		if (event_add(&sock->ev, NULL) < 0) {
			syslog(LOG_WARNING, "tcp socket event_add");
			rc = -EIO;
			goto err_out;
		}

		chunkd_srv.sockets =
			g_list_append(chunkd_srv.sockets, sock);
	}

	freeaddrinfo(res0);

	return 0;

err_out:
	return rc;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	GList *tmpl;

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

	if ((!(chunkd_srv.flags & SFL_FOREGROUND)) && (daemon(1, 0) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(chunkd_srv.pid_file);
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

	INIT_LIST_HEAD(&chunkd_srv.wr_trash);
	chunkd_srv.trash_sz = 0;

	/* set up server networking */
	tmpl = chunkd_srv.listeners;
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

	rc = 0;

err_out_pid:
	unlink(chunkd_srv.pid_file);
err_out:
	closelog();
	return rc;
}


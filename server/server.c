
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

#include "cld-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <locale.h>
#include <argp.h>
#include <netdb.h>
#include "cld.h"

#define PROGRAM_NAME "cld"

#define CLD_DEF_PORT "8081"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLD_RAW_MSG_SZ		= 4096,
};

static struct argp_option options[] = {
	{ "data", 'd', "DIRECTORY", 0,
	  "Store database environment in DIRECTORY" },
	{ "debug", 'D', NULL, 0,
	  "Enable debug output" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "port", 'p', "PORT", 0,
	  "bind to UDP port PORT" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - coarse locking daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool am_master = true;
static bool dump_stats;
int debugging = 0;
time_t current_time;

struct server cld_srv = {
	.data_dir		= "/spare/tmp/cld/lib",
	.pid_file		= "/var/run/cld.pid",
	.port			= CLD_DEF_PORT,
};

int udp_tx(struct server_socket *sock, struct sockaddr *addr,
	   socklen_t addr_len, const void *data, size_t data_len)
{
	ssize_t src;

	src = sendto(sock->fd, data, data_len, 0, addr, addr_len);
	if (src < 0 && errno != EAGAIN)
		syslogerr("sendto");

	if (src < 0)
		return -errno;

	return 0;
}

void resp_copy(struct cld_msg_resp *resp, const struct cld_msg_hdr *src)
{
	memcpy(&resp->hdr, src, sizeof(*src));
	resp->code = 0;
	resp->rsv = 0;
	resp->seqid_in = src->seqid;
}

void resp_err(struct server_socket *sock, struct session *sess,
		     struct cld_msg_hdr *msg, enum cle_err_codes errcode)
{
	struct cld_msg_resp resp;

	resp_copy(&resp, msg);
	resp.hdr.seqid = next_seqid_le(&sess->next_seqid_out);
	resp.code = GUINT32_TO_LE(errcode);

	sess_sendmsg(sess, &resp, sizeof(resp), true);
}

void resp_ok(struct server_socket *sock, struct session *sess,
		    struct cld_msg_hdr *msg)
{
	resp_err(sock, sess, msg, CLE_OK);
}

static bool udp_rx(struct server_socket *sock, DB_TXN *txn,
		   const struct client *cli,
		   uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_hdr *msg = (struct cld_msg_hdr *) raw_msg;
	struct session *sess = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	struct cld_msg_resp resp;
	struct msg_params mp;

	if (msg_len < sizeof(*msg)) {
		resp_rc = CLE_BAD_PKT;
		goto err_out;
	}
	if (memcmp(msg->magic, CLD_MAGIC, sizeof(msg->magic))) {
		resp_rc = CLE_BAD_PKT;
		goto err_out;
	}

	/* look up client session, verify it matches IP */
	sess = g_hash_table_lookup(cld_srv.sessions, msg->sid);
	if (sess && ((sess->addr_len != cli->addr_len) ||
	    memcmp(&sess->addr, &cli->addr, sess->addr_len))) {
		resp_rc = CLE_SESS_INVAL;
		goto err_out;
	}

	mp.sock = sock;
	mp.cli = cli;
	mp.txn = txn;
	mp.sess = sess;
	mp.msg = raw_msg;
	mp.msg_len = msg_len;

	if (msg->op != cmo_new_sess) {
		if (!sess) {
			resp_rc = CLE_SESS_INVAL;
			goto err_out;
		}

		sess->last_contact = time(NULL);

		if (msg->op != cmo_ack) {
			/* eliminate duplicates; do not return any response */
			if (GUINT64_FROM_LE(msg->seqid) != sess->next_seqid_in)
				return false;

			/* received message - update session */
			sess->next_seqid_in++;
		}
	} else {
		if (sess) {
			resp_rc = CLE_SESS_EXISTS;
			goto err_out;
		}
	}

	switch(msg->op) {
	case cmo_nop:
		resp_ok(sock, sess, msg);
		break;

	case cmo_new_sess:
		return msg_new_sess(&mp, cli);

	case cmo_end_sess: {
		int rc;

		/* transmit response (once, without retries) */
		resp_copy(&resp, msg);
		resp.hdr.seqid = next_seqid_le(&sess->next_seqid_out);

		rc = session_dispose(txn, sess);

		resp.code = GUINT32_TO_LE(rc == 0 ? CLE_OK : CLE_DB_ERR);
		udp_tx(sock, (struct sockaddr *) &cli->addr, cli->addr_len,
		       &resp, sizeof(resp));

		return (rc == 0) ? true : false;
	}

	case cmo_open:
		return msg_open(&mp);
	case cmo_get:
		return msg_get(&mp, false);
	case cmo_get_meta:
		return msg_get(&mp, true);
	case cmo_put:
		return msg_put(&mp);
	case cmo_data:
		return msg_data(&mp);
	case cmo_close:
		return msg_close(&mp);
	case cmo_del:
		return msg_del(&mp);
	case cmo_unlock:
		return msg_unlock(&mp);
	case cmo_lock:
		return msg_lock(&mp, true);
	case cmo_trylock:
		return msg_lock(&mp, false);
	case cmo_ack:
		return msg_ack(&mp);
	default:
		return false;
	}

	return true;

err_out:
	/* transmit error response (once, without retries) */
	resp_copy(&resp, msg);
	resp.hdr.seqid = GUINT64_TO_LE(0xdeadbeef);
	resp.code = GUINT32_TO_LE(resp_rc);
	udp_tx(sock, (struct sockaddr *) &cli->addr, cli->addr_len,
	       &resp, sizeof(resp));

	return false;
}

static void udp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	struct client cli;
	char host[64];
	ssize_t rrc;
	struct msghdr hdr;
	struct iovec iov[2];
	uint8_t raw_msg[CLD_RAW_MSG_SZ], ctl_msg[CLD_RAW_MSG_SZ];
	int rc;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	const char *dberrmsg;

	current_time = time(NULL);

	memset(&cli, 0, sizeof(cli));

	iov[0].iov_base = raw_msg;
	iov[0].iov_len = sizeof(raw_msg);

	hdr.msg_name = &cli.addr;
	hdr.msg_namelen = sizeof(cli.addr);
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = ctl_msg;
	hdr.msg_controllen = sizeof(ctl_msg);

	rrc = recvmsg(sock->fd, &hdr, 0);
	if (rrc < 0) {
		syslogerr("UDP recvmsg");
		return;
	}
	cli.addr_len = hdr.msg_namelen;

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli.addr, cli.addr_len,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;

	strcpy(cli.addr_host, host);

	if (debugging)
		syslog(LOG_DEBUG, "client %s message", host);

	if (am_master) {
		rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
		if (rc) {
			dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
			return;
		}

		if (udp_rx(sock, txn, &cli, raw_msg, rrc)) {
			rc = txn->commit(txn, 0);
			dberrmsg = "DB_ENV->txn_commit";
		} else {
			rc = txn->abort(txn);
			dberrmsg = "DB_ENV->txn_abort";
		}
		if (rc)
			dbenv->err(dbenv, rc, dberrmsg);
	} else {
		struct cld_msg_hdr *msg = (struct cld_msg_hdr *) raw_msg;
		struct cld_msg_resp resp;

		/* transmit not-master error msg */
		resp_copy(&resp, msg);
		resp.hdr.seqid = GUINT64_TO_LE(0xdeadbeef);
		resp.hdr.op = cmo_not_master;
		udp_tx(sock, (struct sockaddr *) &cli.addr, cli.addr_len,
		       &resp, sizeof(resp));
	}
}

static void add_chkpt_timer(void)
{
	struct timeval tv = { CLD_CHKPT_SEC, 0 };

	if (evtimer_add(&cld_srv.chkpt_timer, &tv) < 0)
		syslog(LOG_WARNING, "unable to add checkpoint timer");
}

static void cldb_checkpoint(int fd, short events, void *userdata)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	int rc;

	if (debugging)
		syslog(LOG_INFO, "db4 checkpoint");

	/* flush logs to db, if log files >= 1MB */
	rc = dbenv->txn_checkpoint(dbenv, 1024, 0, 0);
	if (rc)
		dbenv->err(dbenv, rc, "txn_checkpoint");

	/* reactivate timer, to call ourselves again */
	add_chkpt_timer();
}

static int net_open(void)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, cld_srv.port, &hints, &res0);
	if (rc) {
		syslog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       cld_srv.port, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
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
			syslogerr("tcp bind");
			rc = -errno;
			goto err_out;
		}

		rc = fsetflags("udp server", fd, O_NONBLOCK);
		if (rc)
			goto err_out;

		sock = calloc(1, sizeof(*sock));
		if (!sock) {
			rc = -ENOMEM;
			goto err_out;
		}

		sock->fd = fd;

		event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
			  udp_srv_event, sock);

		if (event_add(&sock->ev, NULL) < 0) {
			syslog(LOG_WARNING, "tcp socket event_add");
			rc = -errno;
			goto err_out;
		}

		cld_srv.sockets =
			g_list_append(cld_srv.sockets, sock);
	}

	freeaddrinfo(res0);

	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
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
	syslog(LOG_INFO, "STAT %s %lu", #stat, cld_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
}

#undef X

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'd':
		cld_srv.data_dir = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'F':
		cld_srv.flags |= SFL_FOREGROUND;
		break;
	case 'p':
		if (atoi(arg) > 0 && atoi(arg) < 65536)
			cld_srv.port = arg;
		else {
			fprintf(stderr, "invalid port %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		cld_srv.pid_file = arg;
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

static void cldb_init(void)
{
	cld_srv.cldb.home = cld_srv.data_dir;
	if (cldb_open(&cld_srv.cldb,
		      DB_CREATE | DB_THREAD | DB_RECOVER,
		      DB_CREATE | DB_THREAD,
		      "cld", true))
		exit(1);
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	current_time = time(NULL);
	srand(current_time ^ getpid());

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

	if ((!(cld_srv.flags & SFL_FOREGROUND)) && (daemon(1, 0) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(cld_srv.pid_file);
	if (rc < 0)
		goto err_out;

	/*
	 * properly capture TERM and other signals
	 */

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	event_init();

	cldb_init();

	evtimer_set(&cld_srv.chkpt_timer, cldb_checkpoint, NULL);
	add_chkpt_timer();

	cld_srv.sessions = g_hash_table_new(sess_hash, sess_equal);
	cld_srv.timers = g_queue_new();
	if (!cld_srv.sessions || !cld_srv.timers)
		goto err_out_pid;

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_pid;

	syslog(LOG_INFO, "initialized");

	while (server_running) {
		event_dispatch();

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
	}

	syslog(LOG_INFO, "shutting down");

	cldb_close(&cld_srv.cldb);

	rc = 0;

err_out_pid:
	unlink(cld_srv.pid_file);
err_out:
	closelog();
	return rc;
}


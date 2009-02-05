
#include "cld-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <locale.h>
#include <argp.h>
#include <netdb.h>
#include "cldb.h"
#include "cld.h"

#define PROGRAM_NAME "cld"

#define CLD_DEF_PORT "8081"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	TABLED_EPOLL_INIT_SIZE	= 200,		/* passed to epoll_create(2) */
	TABLED_EPOLL_MAX_EVT	= 100,		/* max events per poll */
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
static bool dump_stats;
int debugging = 0;

struct server cld_srv = {
	.data_dir		= "/spare/tmp/cld/lib",
	.pid_file		= "/spare/tmp/cld/run/tabled.pid",
	.port			= CLD_DEF_PORT,
};

static struct client *cli_alloc(void)
{
	return calloc(1, sizeof(struct client));
}

static void udp_event(unsigned int events, struct server_socket *sock)
{
	struct client *cli;
	char host[64];

	/* alloc and init client info */
	cli = cli_alloc();
	if (!cli)
		goto err_out;

	/* FIXME: fill in cli->addr */

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, sizeof(struct sockaddr_in6),
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;

	if (debugging)
		syslog(LOG_DEBUG, "client %s message", host);

	strcpy(cli->addr_host, host);

	return;

err_out:
	syslog(LOG_INFO, "client %s message error", host);
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

		if (listen(fd, 100) < 0) {
			syslogerr("tcp listen");
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
		sock->poll.poll_type = spt_udp;
		sock->poll.u.sock = sock;
		sock->evt.events = EPOLLIN;
		sock->evt.data.ptr = &sock->poll;

		rc = epoll_ctl(cld_srv.epoll_fd, EPOLL_CTL_ADD, fd,
			       &sock->evt);
		if (rc < 0) {
			syslogerr("tcp socket epoll_ctl");
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

static void handle_event(unsigned int events, void *event_data)
{
	struct server_poll *sp = event_data;

	cld_srv.stats.event++;

	switch (sp->poll_type) {
	case spt_udp:
		udp_event(events, sp->u.sock);
		break;
	}
}

static void term_signal(int signal)
{
	server_running = false;
}

static void stats_signal(int signal)
{
	dump_stats = true;
}

#define X(stat) \
	syslog(LOG_INFO, "STAT %s %lu", #stat, cld_srv.stats.stat)

static void log_stats(void)
{
	X(poll);
	X(event);
	X(max_evt);
}

#undef X

static void main_loop(void)
{
	struct epoll_event evt[TABLED_EPOLL_MAX_EVT];
	int rc, i;

	while (server_running) {
		rc = epoll_wait(cld_srv.epoll_fd, evt, TABLED_EPOLL_MAX_EVT, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;

			syslogerr("epoll_wait");
			return;
		}

		if (rc == TABLED_EPOLL_MAX_EVT)
			cld_srv.stats.max_evt++;
		cld_srv.stats.poll++;

		for (i = 0; i < rc; i++)
			handle_event(evt[i].events, evt[i].data.ptr);

		if (dump_stats) {
			log_stats();
			dump_stats = false;
		}
	}
}

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
	if (cldb_open(&cld_srv.cldb, DB_RECOVER | DB_CREATE, DB_CREATE,
		      "cld", true))
		exit(1);
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

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

	cldb_init();

	/* create master epoll fd */
	cld_srv.epoll_fd = epoll_create(TABLED_EPOLL_INIT_SIZE);
	if (cld_srv.epoll_fd < 0) {
		syslogerr("epoll_create");
		goto err_out_pid;
	}

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_epoll;

	syslog(LOG_INFO, "initialized");

	main_loop();

	syslog(LOG_INFO, "shutting down");

	cldb_close(&cld_srv.cldb);

	rc = 0;

err_out_epoll:
	close(cld_srv.epoll_fd);
err_out_pid:
	unlink(cld_srv.pid_file);
err_out:
	closelog();
	return rc;
}


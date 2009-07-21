
#include "cld-config.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <argp.h>
#include <poll.h>
#include <locale.h>
#include <syslog.h>
#include <ctype.h>
#include <cldc.h>

#define PROGRAM_NAME "cld"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

const char *argp_program_version = PACKAGE_VERSION;

enum thread_codes {
	TC_OK,
	TC_FAILED
};

static struct argp_option options[] = {
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max verbose)" },
	{ "host", 'h', "HOST", 0,
	  "Connect to remote host.  Used once in normal case (DNS SRV records), or may be specified multiple times." },
	{ "user", 'u', "USER", 0,
	  "Set username to USER" },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - command line interface to coarse locking service";

struct db_remote {
	char		*host;
	unsigned short	port;
};

static unsigned long thread_running = 1;
static int debugging;
static GList *host_list;
static char clicwd[1024] = "/";
static int to_thread[2], from_thread[2];
static GThread *cldthr;
static char our_user[CLD_MAX_USERNAME + 1] = "cli_user";

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

/* The format comes with a trailing newline, but fortunately syslog strips it */
void cld_p_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

static void handle_user_command(void)
{
}

static int cb_new_sess(struct cldc_call_opts *copts, enum cle_err_codes rc)
{
	return -1;
}

static struct cldc_ops cld_ops = {
	.printf		= cld_p_log,
};

static gpointer cld_thread(gpointer dummy)
{
	struct cldc_udp *udp = NULL;
	struct db_remote *dr;
	struct cldc_call_opts copts = { .cb = cb_new_sess };
	char tcode = TC_FAILED;
	struct pollfd pfd[2];

	if (!host_list) {
		fprintf(stderr, "cldthr: no host list\n");
		write(to_thread[1], &tcode, 1);
		return NULL;
	}

	dr = host_list->data;

	if (cldc_udp_new(dr->host, dr->port, &udp)) {
		fprintf(stderr, "cldthr: UDP create failed\n");
		write(to_thread[1], &tcode, 1);
		return NULL;
	}

	if (cldc_new_sess(&cld_ops, &copts, udp->addr, udp->addr_len,
			  "cldcli", "cldcli", NULL, &udp->sess)) {
		fprintf(stderr, "cldthr: new_sess failed\n");
		write(to_thread[1], &tcode, 1);
		return NULL;
	}

	pfd[0].fd = udp->fd;
	pfd[0].events = POLLIN;

	pfd[1].fd = to_thread[0];
	pfd[1].events = POLLIN;

	while (thread_running) {
		int i, rc;

		/* zero revents.  necessary??? */
		for (i = 0; i < ARRAY_SIZE(pfd); i++)
			pfd[i].revents = 0;

		/* poll for activity */
		rc = poll(pfd, 2, -1);
		if (rc < 0) {
			perror("poll");
			return NULL;
		}

		/* dispatch if activity found */
		for (i = 0; i < ARRAY_SIZE(pfd); i++) {
			if (pfd[i].revents) {
				if (i == 0)
					cldc_udp_receive_pkt(udp);
				else
					handle_user_command();
			}
		}
	}

	return NULL;
}

static void cmd_cd(const char *arg)
{
}

static void cmd_ls(const char *arg)
{
}

static void cmd_cat(const char *arg)
{
}

static bool push_host(const char *arg)
{
	char *colon;
	unsigned int port;
	struct db_remote *dr;

	dr = malloc(sizeof(*dr));
	if (!dr)
		return false;
	dr->host = strdup(arg);
	if (!dr->host)
		goto err_out;

	colon = strrchr(dr->host, ':');
	if (!colon)
		goto err_out_host;

	if (sscanf(colon, ":%u", &port) != 1)
		goto err_out_host;
	if (port < 1 || port > 65535)
		goto err_out_host;

	dr->port = port;

	*colon = 0;

	host_list = g_list_append(host_list, dr);

	return true;

err_out_host:
	free(dr->host);
err_out:
	free(dr);
	return false;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'D':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			debugging = atoi(arg);
		else {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		if (!push_host(arg)) {
			fprintf(stderr, "invalid host: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		if (strlen(arg) >= CLD_MAX_USERNAME) {
			fprintf(stderr, "invalid user: '%s'\n", arg);
			argp_usage(state);
		} else
			strcpy(our_user, arg);
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

static void prompt(void)
{
	fprintf(stderr, "[%s %s]$ ", our_user, clicwd);
	fflush(stderr);
}

static char linebuf[1024];

int main (int argc, char *argv[])
{
	error_t aprc;
	char tcode;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	srand(time(NULL) ^ getpid());

	g_thread_init(NULL);

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if ((pipe(from_thread) < 0) || (pipe(to_thread) < 0)) {
		perror("pipe");
		return 1;
	}

	cldthr = g_thread_create(cld_thread, NULL, TRUE, NULL);
	if (!cldthr) {
		fprintf(stderr, "thread creation failed\n");
		return 1;
	}

	fprintf(stderr, "Waiting for thread startup...\n");
	errno = 0;
	if (read(from_thread[0], &tcode, 1) != 1) {
		perror("read");
		return 1;
	}
	if (tcode != TC_OK) {
		fprintf(stderr, "thread startup failed\n");
		return 1;
	}

	prompt();

	while (fgets(linebuf, sizeof(linebuf), stdin) != NULL) {
		size_t linelen;
		char *s, *tok1, *tok2;

		/* trim trailing whitespace */
		linelen = strlen(linebuf);
		while (linelen && isspace(linebuf[linelen - 1])) {
			linelen--;
			linebuf[linelen] = 0;
		}

		/* skip blank and comment lines */
		if (linebuf[0] == 0 || linebuf[0] == '#')
			continue;

		/* skip leading spaces, find first token */
		s = linebuf;
		while (*s && (isspace(*s)))
			s++;
		tok1 = s;

		/* find remaining tokens, if any */
		while (*s && (!isspace(*s)))
			s++;
		if (*s) {
			*s = 0;
			s++;
		}
		while (*s && (isspace(*s)))
			s++;
		tok2 = s;

		/* dispatch command */
		if (!strcmp(tok1, "cd"))
			cmd_cd(tok2);
		else if (!strcmp(tok1, "ls"))
			cmd_ls(tok2);
		else if (!strcmp(tok1, "cat"))
			cmd_cat(tok2);
		else {
			fprintf(stderr, "INVALID COMMAND: %s %s\n",
				tok1, tok2);
		}

		prompt();
	}

	thread_running = 0;

	return 0;
}


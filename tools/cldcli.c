
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
#include <stdarg.h>
#include <ctype.h>
#include <cldc.h>

#define PROGRAM_NAME "cld"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLD_PATH_MAX		= 1024,
};

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

enum creq_cmd {
	CREQ_CD,
	CREQ_CAT,
	CREQ_LS,
};

struct creq {
	enum creq_cmd	cmd;
	union {
		char path[CLD_PATH_MAX + 1];
	} u;
};

struct cresp {
	enum thread_codes	tcode;
	union {
		unsigned int	file_len;
		unsigned int	n_records;
	} u;
};

struct ls_rec {
	uint64_t		last_mod;
	uint64_t		size;
	char			name[CLD_INODE_NAME_MAX + 1];
};

static unsigned long thread_running = 1;
static int debugging;
static GList *host_list;
static char clicwd[CLD_PATH_MAX + 1] = "/";
static int to_thread[2], from_thread[2];
static GThread *cldthr;
static char our_user[CLD_MAX_USERNAME + 1] = "cli_user";

/* globals only for use in thread */
static struct cldc_udp *udp;
static struct cldc_fh *fh;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

void cld_p_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static int cb_ok_done(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };

	if (errc == CLE_OK)
		cresp.tcode = TC_OK;

	write(from_thread[1], &cresp, sizeof(cresp));

	return 0;
}

static int cb_ls_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	/* FIXME */
	return 0;
}

static int cb_cat_2(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };

	if (errc != CLE_OK) {
		write(from_thread[1], &cresp, sizeof(cresp));
		return 0;
	}

	cresp.tcode = TC_OK;
	cresp.u.file_len = copts_in->u.get.size;

	write(from_thread[1], &cresp, sizeof(cresp));
	write(from_thread[1], copts_in->u.get.buf, copts_in->u.get.size);

	/* FIXME: race; should wait until close succeeds/fails before
	 * returning any data.  'fh' may still be in use, otherwise.
	 */
	cldc_close(fh, &copts);

	return 0;
}

static int cb_cat_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_cat_2, };

	if (errc != CLE_OK) {
		write(from_thread[1], &cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_get(fh, &copts, false)) {
		write(from_thread[1], &cresp, sizeof(cresp));
		return 0;
	}

	return 0;
}

static int cb_cd_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_ok_done, };

	if (errc != CLE_OK) {
		write(from_thread[1], &cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_close(fh, &copts)) {
		write(from_thread[1], &cresp, sizeof(cresp));
		return 0;
	}

	return 0;
}

static void handle_user_command(void)
{
	struct creq creq;
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };
	int rc;

	read(to_thread[0], &creq, sizeof(creq));

	switch (creq.cmd) {
	case CREQ_CD:
		copts.cb = cb_cd_1;
		rc = cldc_open(udp->sess, &copts, creq.u.path,
			       COM_DIRECTORY, 0, &fh);
		if (rc) {
			write(from_thread[1], &cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_CAT:
		copts.cb = cb_cat_1;
		rc = cldc_open(udp->sess, &copts, creq.u.path,
			       COM_READ, 0, &fh);
		if (rc) {
			write(from_thread[1], &cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_LS:
		copts.cb = cb_ls_1;
		rc = cldc_open(udp->sess, &copts, creq.u.path,
			       COM_DIRECTORY, 0, &fh);
		if (rc) {
			write(from_thread[1], &cresp, sizeof(cresp));
			return;
		}
		break;
	}
}

static int cb_new_sess(struct cldc_call_opts *copts, enum cle_err_codes errc)
{
	char tcode = TC_FAILED;

	if (errc != CLE_OK) {
		write(from_thread[1], &tcode, 1);
		return 0;
	}

	/* signal we are up and ready for commands */
	tcode = TC_OK;
	write(from_thread[1], &tcode, 1);

	return 0;
}

static struct cldc_ops cld_ops = {
	.printf		= cld_p_log,
};

static gpointer cld_thread(gpointer dummy)
{
	struct db_remote *dr;
	struct cldc_call_opts copts = { .cb = cb_new_sess };
	char tcode = TC_FAILED;
	struct pollfd pfd[2];

	if (!host_list) {
		fprintf(stderr, "cldthr: no host list\n");
		write(from_thread[1], &tcode, 1);
		return NULL;
	}

	dr = host_list->data;

	if (cldc_udp_new(dr->host, dr->port, &udp)) {
		fprintf(stderr, "cldthr: UDP create failed\n");
		write(from_thread[1], &tcode, 1);
		return NULL;
	}

	if (cldc_new_sess(&cld_ops, &copts, udp->addr, udp->addr_len,
			  "cldcli", "cldcli", NULL, &udp->sess)) {
		fprintf(stderr, "cldthr: new_sess failed\n");
		write(from_thread[1], &tcode, 1);
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
	struct creq creq;
	struct cresp cresp;

	if (!*arg)
		strcpy(creq.u.path, "/");
	else if (*arg != '/') {
		size_t len = snprintf(creq.u.path, sizeof(creq.u.path),
				      "%s/%s", clicwd, arg);
		if (len >= sizeof(creq.u.path)) {
			fprintf(stderr, "%s: path too long\n", arg);
			return;
		}
	} else
		strcpy(creq.u.path, arg);

	creq.cmd = CREQ_CD;

	/* send message to thread */
	write(to_thread[1], &creq, sizeof(creq));

	/* wait for and receive response from thread */
	read(from_thread[0], &cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: change dir failed\n", arg);
		return;
	}

	strcpy(clicwd, arg);
}

static void show_lsr(const struct ls_rec *lsr)
{
	time_t t = lsr->last_mod;
	struct tm tm;
	char last_mod[128];

	localtime_r(&t, &tm);

	strftime(last_mod, sizeof(last_mod), "%F %T", &tm);

	fprintf(stdout, "\t%8llu\t%s %s\n",
		(unsigned long long) lsr->size,
		last_mod,
		lsr->name);
}

static void cmd_ls(const char *arg)
{
	struct creq creq;
	struct cresp cresp;
	size_t len;
	int i;

	if (!*arg) {
		fprintf(stderr, "ls: argument required\n");
		return;
	}

	len = snprintf(creq.u.path, sizeof(creq.u.path), "%s/%s", clicwd, arg);
	if (len >= sizeof(creq.u.path)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_LS;

	/* send message to thread */
	write(to_thread[1], &creq, sizeof(creq));

	/* wait for and receive response from thread */
	read(from_thread[0], &cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: ls failed\n", arg);
		return;
	}

	for (i = 0; i < cresp.u.n_records; i++) {
		struct ls_rec lsr;

		read(from_thread[0], &lsr, sizeof(lsr));

		show_lsr(&lsr);
	}
}

static void cmd_cat(const char *arg)
{
	struct creq creq;
	struct cresp cresp;
	size_t len;
	void *mem;

	if (!*arg) {
		fprintf(stderr, "cat: argument required\n");
		return;
	}

	len = snprintf(creq.u.path, sizeof(creq.u.path), "%s/%s", clicwd, arg);
	if (len >= sizeof(creq.u.path)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_CAT;

	/* send message to thread */
	write(to_thread[1], &creq, sizeof(creq));

	/* wait for and receive response from thread */
	read(from_thread[0], &cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: cat failed\n", arg);
		return;
	}

	len = cresp.u.file_len;
	mem = malloc(len);
	if (!len) {
		fprintf(stderr, "oom\n");
		return;
	}

	/* read file data from thread */
	read(from_thread[0], mem, len);

	/* write file data to stdout */
	fwrite(mem, len, 1, stdout);
	fprintf(stdout, "\n");

	free(mem);
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

static char linebuf[CLD_PATH_MAX + 1];

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


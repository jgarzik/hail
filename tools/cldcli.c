
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
"cldcli - command line interface to coarse locking service";

enum creq_cmd {
	CREQ_CD,
	CREQ_CAT,
	CREQ_LS,
	CREQ_RM,
	CREQ_MKDIR,
};

struct creq {
	enum creq_cmd	cmd;
	union {
		char path[CLD_PATH_MAX + 1];
	} u;
};

struct cresp {
	enum thread_codes	tcode;
	char			msg[64];
	union {
		unsigned int	file_len;
		unsigned int	n_records;
	} u;
};

struct ls_rec {
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
static struct cldc_udp *thr_udp;
static struct cldc_fh *thr_fh;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static const char *names_cle_err[] = {
	[CLE_OK]		= "CLE_OK",
	[CLE_SESS_EXISTS]	= "CLE_SESS_EXISTS",
	[CLE_SESS_INVAL]	= "CLE_SESS_INVAL",
	[CLE_DB_ERR]		= "CLE_DB_ERR",
	[CLE_BAD_PKT]		= "CLE_BAD_PKT",
	[CLE_INODE_INVAL]	= "CLE_INODE_INVAL",
	[CLE_NAME_INVAL]	= "CLE_NAME_INVAL",
	[CLE_OOM]		= "CLE_OOM",
	[CLE_FH_INVAL]		= "CLE_FH_INVAL",
	[CLE_DATA_INVAL]	= "CLE_DATA_INVAL",
	[CLE_LOCK_INVAL]	= "CLE_LOCK_INVAL",
	[CLE_LOCK_CONFLICT]	= "CLE_LOCK_CONFLICT",
	[CLE_LOCK_PENDING]	= "CLE_LOCK_PENDING",
	[CLE_MODE_INVAL]	= "CLE_MODE_INVAL",
	[CLE_INODE_EXISTS]	= "CLE_INODE_EXISTS",
	[CLE_DIR_NOTEMPTY]	= "CLE_DIR_NOTEMPTY",
	[CLE_INTERNAL_ERR]	= "CLE_INTERNAL_ERR",
	[CLE_TIMEOUT]		= "CLE_TIMEOUT",
	[CLE_SIG_INVAL]		= "CLE_SIG_INVAL",
};

static void errc_msg(struct cresp *cresp, enum cle_err_codes errc)
{
	strcpy(cresp->msg, names_cle_err[errc]);
}

static void app_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void do_write(int fd, const void *buf, size_t buflen, const char *msg)
{
	ssize_t rc;

	rc = write(fd, buf, buflen);
	if (rc < 0)
		perror(msg);
	else if (rc != buflen)
		fprintf(stderr, "%s: short write\n", msg);
}

static void do_read(int fd, void *buf, size_t buflen, const char *msg)
{
	ssize_t rc;

	rc = read(fd, buf, buflen);
	if (rc < 0)
		perror(msg);
	else if (rc != buflen)
		fprintf(stderr, "%s: short read\n", msg);
}

/* send message thread -> main */
static void write_from_thread(const void *buf, size_t buflen)
{
	do_write(from_thread[1], buf, buflen, "write-from-thread");
}

/* send message main -> thread */
static void write_to_thread(const void *buf, size_t buflen)
{
	do_write(to_thread[1], buf, buflen, "write-to-thread");
}

/* receive message thread -> main */
static void read_from_thread(void *buf, size_t buflen)
{
	do_read(from_thread[0], buf, buflen, "read-from-thread");
}

/* receive message main -> thread */
static void read_to_thread(void *buf, size_t buflen)
{
	do_read(to_thread[0], buf, buflen, "read-to-thread");
}

static int cb_ok_done(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };

	if (errc == CLE_OK)
		cresp.tcode = TC_OK;
	errc_msg(&cresp, errc);

	write_from_thread(&cresp, sizeof(cresp));

	return 0;
}

static int cb_ls_2(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };
	struct cld_dirent_cur dc;
	int rc, i;
	bool first = true;

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	rc = cldc_dirent_count(copts_in->u.get.buf, copts_in->u.get.size);
	if (rc < 0) {
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	cresp.tcode = TC_OK;
	cresp.u.n_records = rc;

	write_from_thread(&cresp, sizeof(cresp));

	cldc_dirent_cur_init(&dc, copts_in->u.get.buf, copts_in->u.get.size);

	for (i = 0; i < rc; i++) {
		struct ls_rec lsr;
		char *s;

		if (first) {
			first = false;
			
			if (cldc_dirent_first(&dc) < 0)
				break;
		} else {
			if (cldc_dirent_next(&dc) < 0)
				break;
		}

		s = cldc_dirent_name(&dc);
		strcpy(lsr.name, s);
		free(s);

		write_from_thread(&lsr, sizeof(lsr));

	}

	cldc_dirent_cur_fini(&dc);

	/* FIXME: race; should wait until close succeeds/fails before
	 * returning any data.  'fh' may still be in use, otherwise.
	 */
	cldc_close(thr_fh, &copts);

	return 0;
}

static int cb_ls_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_ls_2, };

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_get(thr_fh, &copts, false)) {
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	return 0;
}

static int cb_cat_2(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	cresp.tcode = TC_OK;
	cresp.u.file_len = copts_in->u.get.size;

	write_from_thread(&cresp, sizeof(cresp));
	write_from_thread(copts_in->u.get.buf, copts_in->u.get.size);

	/* FIXME: race; should wait until close succeeds/fails before
	 * returning any data.  'fh' may still be in use, otherwise.
	 */
	cldc_close(thr_fh, &copts);

	return 0;
}

static int cb_cat_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_cat_2, };

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_get(thr_fh, &copts, false)) {
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	return 0;
}

static int cb_cd_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_ok_done, };

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_close(thr_fh, &copts)) {
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	return 0;
}

static int cb_mkdir_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };

	if (errc == CLE_OK)
		cresp.tcode = TC_OK;
	errc_msg(&cresp, errc);

	write_from_thread(&cresp, sizeof(cresp));

	/* FIXME: race; should wait until close succeeds/fails before
	 * returning any data.  'fh' may still be in use, otherwise.
	 */
	cldc_close(thr_fh, &copts);

	return 0;
}

static void handle_user_command(void)
{
	struct creq creq;
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };
	int rc;

	read_to_thread(&creq, sizeof(creq));

	if (debugging)
		switch (creq.cmd) {
		case CREQ_CD:
		case CREQ_CAT:
		case CREQ_LS:
		case CREQ_RM:
		case CREQ_MKDIR:
			fprintf(stderr, "DEBUG: thr rx'd path '%s'\n",
				creq.u.path);
			break;
		}

	switch (creq.cmd) {
	case CREQ_CD:
		copts.cb = cb_cd_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.u.path,
			       COM_DIRECTORY, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_CAT:
		copts.cb = cb_cat_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.u.path,
			       COM_READ, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_LS:
		copts.cb = cb_ls_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.u.path,
			       COM_DIRECTORY | COM_READ, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_RM:
		copts.cb = cb_ok_done;
		rc = cldc_del(thr_udp->sess, &copts, creq.u.path);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_MKDIR:
		copts.cb = cb_mkdir_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.u.path,
			       COM_DIRECTORY | COM_CREATE | COM_EXCL, 0,
			       &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	}
}

static int cb_new_sess(struct cldc_call_opts *copts, enum cle_err_codes errc)
{
	char tcode = TC_FAILED;

	if (errc != CLE_OK) {
		write_from_thread(&tcode, 1);
		return 0;
	}

	/* signal we are up and ready for commands */
	tcode = TC_OK;
	write_from_thread(&tcode, 1);

	return 0;
}

static bool cld_p_timer_ctl(void *private, bool add,
			    int (*cb)(struct cldc_session *, void *),
			    void *cb_private, time_t secs)
{
	fprintf(stderr, "FIXME: timer_ctl\n");
	return false;
}

static int cld_p_pkt_send(void *priv, const void *addr, size_t addrlen,
			       const void *buf, size_t buflen)
{
	struct cldc_udp *udp = priv;
	return cldc_udp_pkt_send(udp, addr, addrlen, buf, buflen);
}

static void cld_p_event(void *private, struct cldc_session *sess,
			struct cldc_fh *fh, uint32_t what)
{
	fprintf(stderr, "FIXME: event\n");
}

static void cld_p_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static struct cldc_ops cld_ops = {
	.timer_ctl	= cld_p_timer_ctl,
	.pkt_send	= cld_p_pkt_send,
	.event		= cld_p_event,
	.printf		= cld_p_log,
};

static gpointer cld_thread(gpointer dummy)
{
	struct cldc_host *dr;
	struct cldc_call_opts copts = { .cb = cb_new_sess };
	char tcode = TC_FAILED;
	struct pollfd pfd[2];

	if (!host_list) {
		fprintf(stderr, "cldthr: no host list\n");
		write_from_thread(&tcode, 1);
		return NULL;
	}

	dr = host_list->data;

	if (cldc_udp_new(dr->host, dr->port, &thr_udp)) {
		fprintf(stderr, "cldthr: UDP create failed\n");
		write_from_thread(&tcode, 1);
		return NULL;
	}

	if (cldc_new_sess(&cld_ops, &copts, thr_udp->addr, thr_udp->addr_len,
			  "cldcli", "cldcli", thr_udp, &thr_udp->sess)) {
		fprintf(stderr, "cldthr: new_sess failed\n");
		write_from_thread(&tcode, 1);
		return NULL;
	}

	pfd[0].fd = thr_udp->fd;
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
					cldc_udp_receive_pkt(thr_udp);
				else
					handle_user_command();
			}
		}
	}

	return NULL;
}

static bool make_abs_path(char *dest, size_t dest_len, const char *src)
{
	int len;

	if (src[0] == '/') {
		if (strlen(src) > dest_len)
			return false;

		strcpy(dest, src);
		return true;
	}

	len = snprintf(dest, dest_len, "%s/%s",
		       !strcmp(clicwd, "/") ? "" : clicwd, src);
	if (len >= dest_len)
		return false;
	
	return true;
}

static void cmd_mkdir(const char *arg)
{
	struct creq creq;
	struct cresp cresp;

	if (!*arg) {
		fprintf(stderr, "mkdir: argument required\n");
		return;
	}

	if (!make_abs_path(creq.u.path, sizeof(creq.u.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_MKDIR;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: mkdir failed: %s\n", arg, cresp.msg);
		return;
	}
}

static void cmd_rm(const char *arg)
{
	struct creq creq;
	struct cresp cresp;

	if (!*arg) {
		fprintf(stderr, "rm: argument required\n");
		return;
	}

	if (!make_abs_path(creq.u.path, sizeof(creq.u.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_RM;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: remove failed: %s\n", arg, cresp.msg);
		return;
	}
}

static void cmd_cd(const char *arg)
{
	struct creq creq;
	struct cresp cresp;

	if (!*arg)
		arg = "/";

	if (!make_abs_path(creq.u.path, sizeof(creq.u.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_CD;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: change dir failed: %s\n", arg, cresp.msg);
		return;
	}

	strcpy(clicwd, arg);
}

static void show_lsr(const struct ls_rec *lsr)
{
	fprintf(stdout, "%s\n", lsr->name);
}

static void cmd_ls(const char *arg)
{
	struct creq creq;
	struct cresp cresp;
	int i;

	if (!*arg)
		arg = clicwd;

	if (!make_abs_path(creq.u.path, sizeof(creq.u.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_LS;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: ls failed: %s\n", arg, cresp.msg);
		return;
	}

	for (i = 0; i < cresp.u.n_records; i++) {
		struct ls_rec lsr;

		read_from_thread(&lsr, sizeof(lsr));

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

	if (!make_abs_path(creq.u.path, sizeof(creq.u.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = CREQ_CAT;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s: cat failed: %s\n", arg, cresp.msg);
		return;
	}

	len = cresp.u.file_len;
	mem = malloc(len);
	if (!len) {
		fprintf(stderr, "oom\n");
		return;
	}

	/* read file data from thread */
	read_from_thread(mem, len);

	/* write file data to stdout */
	fwrite(mem, len, 1, stdout);
	fprintf(stdout, "\n");

	free(mem);
}

static void cmd_help(void)
{
	fprintf(stderr,

"cldcli command quick reference\n"
"------------------------------\n"
"cd		Change to root dir\n"
"cd DIR		Change to DIR\n"
"ls		List files in current dir\n"
"ls DIR		List files in DIR\n"
"rm FILE	Delete FILE\n"
"mkdir DIR	Create new directory DIR\n"
"cat FILE	Output contents of FILE\n"
"quit		Exit cldcli\n"
"exit		Exit cldcli\n"
"<end of file>	Exit cldcli\n"
"\n"

		);
}

static bool push_host(const char *arg)
{
	char *colon;
	unsigned int port;
	struct cldc_host *dr;

	dr = malloc(sizeof(*dr));
	if (!dr)
		return false;
	memset(dr, 0, sizeof(*dr));

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

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if (!host_list) {
		enum { hostsz = 64 };
		char hostb[hostsz];

		if (gethostname(hostb, hostsz-1) < 0) {
			fprintf(stderr, "gethostname error: %s\n",
				strerror(errno));
			return 1;
		}
		hostb[hostsz-1] = 0;
		if (cldc_getaddr(&host_list, hostb, debugging, app_log)) {
			fprintf(stderr, "Unable to find a CLD host\n");
			return 1;
		}
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
	if (read(from_thread[0], &tcode, 1) != 1) {
		perror("read");
		return 1;
	}
	if (tcode != TC_OK) {
		fprintf(stderr, "thread startup failed\n");
		return 1;
	}

	fprintf(stderr, "Type 'help' at the prompt to list commands.\n");
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
		else if (!strcmp(tok1, "rm"))
			cmd_rm(tok2);
		else if (!strcmp(tok1, "mkdir"))
			cmd_mkdir(tok2);
		else if (!strcmp(tok1, "cat"))
			cmd_cat(tok2);
		else if (!strcmp(tok1, "help"))
			cmd_help();
		else if (!strcmp(tok1, "quit") || !strcmp(tok1, "exit"))
			break;
		else {
			fprintf(stderr, "INVALID COMMAND: %s %s\n",
				tok1, tok2);
		}

		prompt();
	}

	thread_running = 0;

	return 0;
}


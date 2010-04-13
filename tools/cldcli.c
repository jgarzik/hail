
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
#include "cld-config.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <argp.h>
#include <locale.h>
#include <stdarg.h>
#include <ctype.h>
#include <ncld.h>

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLD_PATH_MAX		= 1024,
};

static struct argp_option options[] = {
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max verbose)" },
	{ "host", 'h', "HOST:PORT", 0,
	  "Connect to remote CLD at specified HOST:PORT" },
	{ "user", 'u', "USER", 0,
	  "Set username to USER" },
	{ "verbose", 'v', NULL, 0,
	  "Enable verbose libcldc output" },
	{ }
};

static const char doc[] =
"cldcli - command line interface to coarse locking service";

#define TAG "cldcli"

enum creq_cmd {
	CREQ_RM,
	CREQ_MKDIR,
	CREQ_UNLOCK,
};

struct creq {
	enum creq_cmd		cmd_unused;
	char			path[CLD_PATH_MAX + 1];
};

struct cldcli_lock_info {
	bool			is_wait;
	struct ncld_fh		*fh;
	uint64_t		id;
	char			path[CLD_PATH_MAX + 1];
};

static GList *host_list;
static char clicwd[CLD_PATH_MAX + 1] = "/";
static char our_user[CLD_MAX_USERNAME + 1] = "cli_user";

/* globals only for use in thread */
static struct ncld_sess *nsess;
static GList *thr_lock_list;
static uint64_t thr_lock_id = 2;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static void applog(int prio, const char *fmt, ...)
{
	char buf[200];
	va_list ap;

	va_start(ap, fmt);
	snprintf(buf, 200, TAG ": %s\n", fmt);
	vfprintf(stderr, buf, ap);
	va_end(ap);
}

static struct hail_log cli_log = {
	.func = applog,
};

static void sess_event(void *private, uint32_t what)
{
	fprintf(stderr, "FIXME: handle event(s) %s%s%s%s%s\n",
		(what & CE_UPDATED) ? "updated " : "",
		(what & CE_DELETED) ? "deleted " : "",
		(what & CE_LOCKED) ? "locked " : "",
		(what & CE_MASTER_FAILOVER) ? "master-fail " : "",
		(what & CE_SESS_FAILED) ? "sess-fail " : "");
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

static void cmd_cd(const char *arg)
{
	struct creq creq = { 0, };
	struct ncld_fh *fh;
	int error;

	if (!*arg)
		arg = "/";

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		return;
	}

	fh = ncld_open(nsess, creq.path, COM_DIRECTORY, &error, 0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				creq.path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				creq.path, error);
		}
		return;
	}
	ncld_close(fh);

	strcpy(clicwd, creq.path);
}

static void cmd_ls(const char *arg)
{
	struct creq creq = { 0, };
	struct ncld_fh *fh;
	struct ncld_read *rp;
	const char *data;
	size_t data_len;
	unsigned int n_records;
	struct cld_dirent_cur dc;
	bool first;
	int error;
	int i;
	int rc;

	if (!*arg)
		arg = clicwd;

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		return;
	}

	fh = ncld_open(nsess, creq.path, COM_DIRECTORY | COM_READ, &error,
			0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				creq.path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				creq.path, error);
		}
		return;
	}

	rp = ncld_get(fh, &error);
	if (!rp) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot get on path `%s': %s\n",
				creq.path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot get on path `%s': %d\n",
				creq.path, error);
		}
		ncld_close(fh);
		return;
	}

	data = rp->ptr;
	data_len = rp->length;

	rc = cldc_dirent_count(data, data_len);
	if (rc < 0) {
		fprintf(stderr, TAG ": cldc_dirent_count failed on path `%s'\n",
				creq.path);
		ncld_read_free(rp);
		ncld_close(fh);
		return;
	}
	n_records = rc;

	cldc_dirent_cur_init(&dc, data, data_len);

	first = true;
	for (i = 0; i < n_records; i++) {
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
		printf("%s\n", s);
		free(s);
	}

	cldc_dirent_cur_fini(&dc);

	ncld_read_free(rp);
	ncld_close(fh);
}

static void cmd_cat(const char *arg)
{
	struct creq creq = { 0, };
	struct ncld_fh *fh;
	struct ncld_read *rp;
	int error;

	if (!*arg) {
		fprintf(stderr, "cat: argument required\n");
		return;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		return;
	}

	fh = ncld_open(nsess, creq.path, COM_READ, &error, 0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				creq.path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				creq.path, error);
		}
		return;
	}

	rp = ncld_get(fh, &error);
	if (!rp) {
		fprintf(stderr, TAG ": cannot read from path `%s': %d\n",
			creq.path, error);
		ncld_close(fh);
		return;
	}

	(void) fwrite(rp->ptr, rp->length, 1, stdout);
	fprintf(stdout, "\n");

	ncld_read_free(rp);
	ncld_close(fh);
}

static void cmd_list_locks(void)
{
	GList *tmp;

	tmp = thr_lock_list;
	while (tmp) {
		struct cldcli_lock_info *li;

		li = tmp->data;
		tmp = tmp->next;

		printf("%llu %s\n", (unsigned long long) li->id, li->path);
	}
}

static void cmd_cpin(const char *cmd, const char *arg)
{
	struct creq creq;
	struct ncld_fh *fh;
	gchar **sv = NULL, *cld_path, *fs_path;
	gchar *fs_content = NULL;
	gsize fs_len = 0;
	int error;
	int rc;

	memset(&creq, 0, sizeof(creq));

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	sv = g_strsplit_set(arg, " \t\f\r\n", 2);
	if (!sv || !sv[0] || !sv[1]) {
		fprintf(stderr, "%s: two arguments required\n", cmd);
		goto out;
	}

	cld_path = sv[1];
	fs_path = sv[0];

	if (!g_file_get_contents(fs_path, &fs_content, &fs_len, NULL)) {
		fprintf(stderr, TAG ": Failed to read data from FS path %s\n",
			fs_path);
		goto out;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), cld_path)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		goto out;
	}

	fh = ncld_open(nsess, creq.path, COM_CREATE | COM_WRITE,
			&error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, TAG ": %s: cannot open: %d\n", creq.path, error);
		goto out;
	}

	rc = ncld_write(fh, fs_content, fs_len);
	if (rc) {
		fprintf(stderr, TAG ": %s(%s -> %s) failed: %d\n",
			cmd, sv[0], sv[1], rc);
		ncld_close(fh);
		goto out;
	}

	ncld_close(fh);

out:
	g_strfreev(sv);
	free(fs_content);
}

static void cmd_cpout(const char *cmd, const char *arg)
{
	struct creq creq;
	struct ncld_fh *fh;
	struct ncld_read *rp;
	gchar **sv = NULL, *cld_path, *fs_path;
	int error;

	memset(&creq, 0, sizeof(creq));

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	sv = g_strsplit_set(arg, " \t\f\r\n", 2);
	if (!sv || !sv[0] || !sv[1]) {
		fprintf(stderr, "%s: two arguments required\n", cmd);
		goto out;
	}

	cld_path = sv[0];
	fs_path = sv[1];

	if (!make_abs_path(creq.path, sizeof(creq.path), cld_path)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		goto out;
	}

	fh = ncld_open(nsess, creq.path, COM_READ, &error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, TAG ": %s: cannot open: %d\n", creq.path, error);
		goto out;
	}
	rp = ncld_get(fh, &error);
	if (!rp) {
		fprintf(stderr, TAG ": cannot read from path `%s': %d\n",
			creq.path, error);
		ncld_close(fh);
		goto out;
	}

	if (!g_file_set_contents(fs_path, rp->ptr, rp->length, NULL)) {
		fprintf(stderr, "Successfully read CLD data from %s,\n"
			"but failed to write data to FS path %s\n",
			cld_path, fs_path);
	}

	ncld_read_free(rp);
	ncld_close(fh);

out:
	g_strfreev(sv);
}

static void cmd_lock(const char *cmd, const char *arg, bool wait_for_lock)
{
	struct creq creq = { 0, };
	struct ncld_fh *fh;
	struct cldcli_lock_info *li;
	int error;
	int rc;

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		return;
	}

	li = calloc(1, sizeof(*li));
	if (!li) {
		fprintf(stderr, TAG ": OOM\n");
		return;
	}

	li->is_wait = wait_for_lock;
	li->id = thr_lock_id++;
	strncpy(li->path, creq.path, CLD_PATH_MAX);

	fh = ncld_open(nsess, creq.path, COM_LOCK, &error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, TAG ": %s: cannot open: %d\n", creq.path, error);
		free(li);
		return;
	}
	li->fh = fh;

	if (wait_for_lock)
		rc = ncld_qlock(fh);
	else
		rc = ncld_trylock(fh);

	if (rc < 0) {
		fprintf(stderr, TAG ": %s: cannot lock: %d\n", creq.path, error);
		ncld_close(fh);
		free(li);
		return;
	}

	if (rc > 0)
		printf("lock %ld queued\n", (long)li->id);

	thr_lock_list = g_list_append(thr_lock_list, li);
}

static void basic_cmd(const char *cmd, const char *arg, enum creq_cmd cmd_no)
{
	struct creq creq = { 0, };
	struct ncld_fh *fh;
	int error;
	int rc;

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, TAG ": %s: path too long\n", arg);
		return;
	}

	switch (cmd_no) {
	case CREQ_RM:
		rc = ncld_del(nsess, creq.path);
		break;
	case CREQ_MKDIR:
		rc = 0;
		fh = ncld_open(nsess, creq.path,
				COM_DIRECTORY | COM_CREATE | COM_EXCL, &error,
				0, NULL, NULL);
		if (fh)
			ncld_close(fh);
		else
			rc = error;
		break;

	case CREQ_UNLOCK: {
		GList *tmp;
		struct cldcli_lock_info *li = NULL;

		tmp = thr_lock_list;
		while (tmp) {
			li = tmp->data;

			if (!strncmp(li->path, creq.path, sizeof(li->path)))
				break;

			tmp = tmp->next;
		}
		if (!tmp) {
			fprintf(stderr, TAG ": no lock found\n");
			return;
		}

		thr_lock_list = g_list_delete_link(thr_lock_list, tmp);

		rc = ncld_unlock(li->fh);
		ncld_close(li->fh);
		free(li);
		break;
		}
	default:
		fprintf(stderr, TAG ": IE unknown cmd %d\n", cmd_no);
		return;
	}

	if (rc) {
		fprintf(stderr, TAG ": %s(%s) failed: %d\n", cmd, arg, rc);
		return;
	}
}

static void cmd_help(void)
{
	fprintf(stderr,

"cldcli command quick reference\n"
"------------------------------\n"
"cat FILE	Output contents of FILE\n"
"cd		Change to root dir\n"
"cd DIR		Change to DIR\n"
"cpin FS-FILE CLD-FILE\n"
"		Copy contents of FS-FILE into CLD as CLD-FILE\n"
"cpout CLD-FILE FS-FILE\n"
"		Copy contents of CLD-FILE out of CLD into FS-FILE\n"
"list locks	List locks currently held by this session\n"
"lock FILE	Obtain exclusive lock on FILE, waiting in b/g if necessary\n"
"ls		List files in current dir\n"
"ls DIR		List files in DIR\n"
"mkdir DIR	Create new directory DIR\n"
"rm FILE	Delete FILE\n"
"trylock FILE	Attempt to obtain exclusive lock on FILE\n"
"unlock FILE	Remove exclusive lock from FILE\n"
"\n"
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
	if (!dr) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, sizeof(*dr));
		goto err;
	}
	memset(dr, 0, sizeof(*dr));

	dr->host = strdup(arg);
	if (!dr->host) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, strlen(arg));
		goto err_out;
	}

	colon = strrchr(dr->host, ':');
	if (!colon) {
		fprintf(stderr, "no port in host specifier `%s'\n", dr->host);
		goto err_out_host;
	}

	if (sscanf(colon, ":%u", &port) != 1) {
		fprintf(stderr, "port `%s' is invalid\n", colon+1);
		goto err_out_host;
	}
	if (port < 1 || port > 65535) {
		fprintf(stderr, "port `%s' is out of range\n", colon+1);
		goto err_out_host;
	}

	dr->port = port;

	*colon = 0;

	host_list = g_list_append(host_list, dr);

	return true;

err_out_host:
	free(dr->host);
err_out:
	free(dr);
err:
	return false;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	int v;

	switch(key) {
	case 'D':
		v = atoi(arg);
		if (v < 0 || v > 2) {
			fprintf(stderr, TAG ": invalid debug level: '%s'\n",
				arg);
			argp_usage(state);
		}
		if (v >= 1)
			cli_log.debug = true;
		if (v >= 2)
			cli_log.verbose = true;
		break;
	case 'h':
		if (!push_host(arg))
			argp_usage(state);
		break;
	case 'u':
		if (strlen(arg) >= CLD_MAX_USERNAME) {
			fprintf(stderr, TAG ": invalid user: '%s'\n", arg);
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
	printf("[%s %s]$ ", our_user, clicwd);
	fflush(stdout);
}

int main (int argc, char *argv[])
{
	char linebuf[CLD_PATH_MAX + 1];
	struct cldc_host *dr;
	error_t aprc;
	int error;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	g_thread_init(NULL);

	ncld_init();

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, TAG ": argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if (!host_list) {
		enum { hostsz = 64 };
		char hostb[hostsz];

		if (gethostname(hostb, hostsz-1) < 0) {
			fprintf(stderr, TAG ": gethostname error: %s\n",
				strerror(errno));
			return 1;
		}
		hostb[hostsz-1] = 0;
		if (cldc_getaddr(&host_list, hostb, &cli_log)) {
			fprintf(stderr, TAG ": Unable to find a CLD host\n");
			return 1;
		}
	}

	printf("Waiting for session startup...\n");
	fflush(stdout);
	dr = host_list->data;

	nsess = ncld_sess_open(dr->host, dr->port, &error, sess_event, NULL,
			     "cldcli", "cldcli", &cli_log);
	if (!nsess) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open CLD session: %s\n",
				strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open CLD session: %d\n",
				error);
		}
		return 1;
	}

	printf("Type 'help' at the prompt to list commands.\n");
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
		if (linebuf[0] == 0 || linebuf[0] == '#') {
			prompt();
			continue;
		}

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
			basic_cmd(tok1, tok2, CREQ_RM);
		else if (!strcmp(tok1, "mkdir"))
			basic_cmd(tok1, tok2, CREQ_MKDIR);
		else if (!strcmp(tok1, "cat"))
			cmd_cat(tok2);
		else if (!strcmp(tok1, "cpin"))
			cmd_cpin(tok1, tok2);
		else if (!strcmp(tok1, "cpout"))
			cmd_cpout(tok1, tok2);
		else if (!strcmp(tok1, "lock"))
			cmd_lock(tok1, tok2, true);
		else if (!strcmp(tok1, "trylock"))
			cmd_lock(tok1, tok2, false);
		else if (!strcmp(tok1, "unlock"))
			basic_cmd(tok1, tok2, CREQ_UNLOCK);
		else if ((!strcmp(tok1, "list")) && tok2 &&
			 (!strcmp(tok2, "locks")))
			cmd_list_locks();
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

	ncld_sess_close(nsess);
	return 0;
}


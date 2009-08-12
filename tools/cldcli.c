
#include "cld-config.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <argp.h>
#include <poll.h>
#include <locale.h>
#include <stdarg.h>
#include <ctype.h>
#include <cldc.h>

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

enum creq_cmd {
	CREQ_CD,
	CREQ_CAT,
	CREQ_LS,
	CREQ_RM,
	CREQ_MKDIR,
	CREQ_CP_FC,		/* cpin: FS-to-CLD copy */
	CREQ_CP_CF,		/* cpout: CLD-to-FS copy */
	CREQ_LOCK,
	CREQ_TRYLOCK,
	CREQ_UNLOCK,
	CREQ_LIST_LOCKS,
};

struct cp_fc_info {
	void		*mem;
	size_t		mem_len;
};

struct creq {
	enum creq_cmd		cmd;
	char			path[CLD_PATH_MAX + 1];
	struct cp_fc_info	cfi;
};

struct cresp {
	enum thread_codes	tcode;
	char			msg[64];
	union {
		size_t		file_len;
		unsigned int	n_records;
		GList		*list;
	} u;
};

struct ls_rec {
	char			name[CLD_INODE_NAME_MAX + 1];
};

struct cldcli_lock_info {
	enum creq_cmd		cmd;
	struct cldc_fh		*fh;
	uint64_t		id;
	char			path[CLD_PATH_MAX + 1];
};

struct timer {
	bool			fired;
	void			(*cb)(struct timer *);
	void			*userdata;
	time_t			expires;
};

static unsigned long thread_running = 1;
static int debugging;
static GList *host_list;
static char clicwd[CLD_PATH_MAX + 1] = "/";
static int to_thread[2], from_thread[2];
static GThread *cldthr;
static char our_user[CLD_MAX_USERNAME + 1] = "cli_user";
static GList *timer_list;
static bool cldcli_verbose;

/* globals only for use in thread */
static struct cldc_udp *thr_udp;
static struct cldc_fh *thr_fh;
static GList *thr_lock_list;
static uint64_t thr_lock_id = 2;
static struct timer thr_timer;
static int (*cldc_timer_cb)(struct cldc_session *, void *);
static void *cldc_timer_private;

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

static void applog(int prio, const char *fmt, ...)
{
	char buf[200];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, 200, fmt, ap);
	fprintf(stderr, "%s\n", buf);
	va_end(ap);
}

static gint timer_cmp(gconstpointer a_, gconstpointer b_)
{
	const struct timer *a = a_;
	const struct timer *b = b_;

	if (a->expires > b->expires)
		return 1;
	if (a->expires == b->expires)
		return 0;
	return -1;
}

static void timer_add(struct timer *timer, time_t expires)
{
	timer->fired = false;
	timer->expires = expires;
	timer_list = g_list_insert_sorted(timer_list, timer, timer_cmp);
}

static void timer_del(struct timer *timer)
{
	timer_list = g_list_remove(timer_list, timer);
}

static time_t timers_run(void)
{
	struct timer *timer;
	time_t now = time(NULL);

	while (timer_list) {
		timer = timer_list->data;
		if (timer->expires > now)
			return (timer->expires - now);

		timer->fired = true;
		timer->cb(timer);

		timer_list = g_list_delete_link(timer_list, timer_list);
	}

	return 0;
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

static int cb_cp_cf_2(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
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

static int cb_cp_cf_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_cp_cf_2, };

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

static int cb_cp_fc_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_ok_done, };
	struct cp_fc_info *cfi = copts_in->private;

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	if (cldc_put(thr_fh, &copts, cfi->mem, cfi->mem_len)) {
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

static int cb_lock_2(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cldcli_lock_info *li = copts_in->private;

	if ((errc == CLE_OK) ||
	    ((li->cmd == CREQ_LOCK) && (errc == CLE_LOCK_PENDING)))
		thr_lock_list = g_list_append(thr_lock_list, li);
	else
		free(li);

	return cb_ok_done(copts_in, errc);
}

static int cb_lock_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { .cb = cb_lock_2, };
	struct cldcli_lock_info *li = copts_in->private;
	bool wait_for_lock = (li->cmd == CREQ_LOCK);

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		return 0;
	}

	copts.private = li;

	if (cldc_lock(li->fh, &copts, 0, wait_for_lock)) {
		write_from_thread(&cresp, sizeof(cresp));
		free(li);
		return 0;
	}

	return 0;
}

static int cb_unlock_1(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cresp cresp = { .tcode = TC_FAILED, };
	struct cldc_call_opts copts = { NULL, };
	struct cldcli_lock_info *li = copts_in->private;

	if (errc != CLE_OK) {
		errc_msg(&cresp, errc);
		write_from_thread(&cresp, sizeof(cresp));
		goto out;
	}

	cresp.tcode = TC_OK;

	write_from_thread(&cresp, sizeof(cresp));

out:
	cldc_close(li->fh, &copts);

	free(li);
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
		case CREQ_CP_FC:
		case CREQ_CP_CF:
		case CREQ_LOCK:
		case CREQ_TRYLOCK:
		case CREQ_UNLOCK:
			fprintf(stderr, "DEBUG: thr rx'd path '%s'\n",
				creq.path);
			break;
		case CREQ_LIST_LOCKS:
			fprintf(stderr, "DEBUG: thr rx'd no path\n");
			break;
		}

	switch (creq.cmd) {
	case CREQ_CD:
		copts.cb = cb_cd_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_DIRECTORY, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_CAT:
		copts.cb = cb_cat_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_READ, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_CP_CF:
		copts.cb = cb_cp_cf_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_READ, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_CP_FC:
		copts.cb = cb_cp_fc_1;
		copts.private = &creq.cfi;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_CREATE | COM_WRITE, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_LS:
		copts.cb = cb_ls_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_DIRECTORY | COM_READ, 0, &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_RM:
		copts.cb = cb_ok_done;
		rc = cldc_del(thr_udp->sess, &copts, creq.path);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_MKDIR:
		copts.cb = cb_mkdir_1;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_DIRECTORY | COM_CREATE | COM_EXCL, 0,
			       &thr_fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}
		break;
	case CREQ_TRYLOCK:
	case CREQ_LOCK: {
		struct cldcli_lock_info *li;

		li = calloc(1, sizeof(*li));
		if (!li) {
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}

		li->cmd = creq.cmd;
		li->id = thr_lock_id++;
		strncpy(li->path, creq.path, sizeof(li->path));

		copts.cb = cb_lock_1;
		copts.private = li;
		rc = cldc_open(thr_udp->sess, &copts, creq.path,
			       COM_LOCK, 0, &li->fh);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			free(li);
			return;
		}

		break;
		}

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
			write_from_thread(&cresp, sizeof(cresp));
			return;
		}

		thr_lock_list = g_list_delete_link(thr_lock_list, tmp);

		copts.cb = cb_unlock_1;
		copts.private = li;
		rc = cldc_unlock(li->fh, &copts);
		if (rc) {
			write_from_thread(&cresp, sizeof(cresp));
			free(li);
			return;
		}

		break;
		}

	case CREQ_LIST_LOCKS: {
		GList *tmp, *content = NULL;

		tmp = thr_lock_list;
		while (tmp) {
			char *s;
			struct cldcli_lock_info *li;

			li = tmp->data;
			tmp = tmp->next;

			s = g_strdup_printf("%llu %s\n",
				 (unsigned long long) li->id,
				 li->path);

			content = g_list_append(content, s);
		}

		cresp.tcode = TC_OK;
		cresp.u.list = content;
		write_from_thread(&cresp, sizeof(cresp));
		break;
		}
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

static void cld_p_timer_cb(struct timer *timer)
{
	int (*timer_cb)(struct cldc_session *, void *) = cldc_timer_cb;
	void *private = cldc_timer_private;

	if (!timer_cb)
		return;

	cldc_timer_cb = NULL;
	cldc_timer_private = NULL;

	timer_cb(thr_udp->sess, private);
}

static bool cld_p_timer_ctl(void *private, bool add,
			    int (*cb)(struct cldc_session *, void *),
			    void *cb_private, time_t secs)
{
	if (add) {
		cldc_timer_cb = cb;
		cldc_timer_private = cb_private;

		thr_timer.fired = false;
		thr_timer.cb = cld_p_timer_cb;
		thr_timer.userdata = NULL;

		timer_add(&thr_timer, time(NULL) + secs);
	} else {
		timer_del(&thr_timer);
	}
	return true;
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

static struct cldc_ops cld_ops = {
	.timer_ctl	= cld_p_timer_ctl,
	.pkt_send	= cld_p_pkt_send,
	.event		= cld_p_event,
	.errlog		= applog,
};

static gpointer cld_thread(gpointer dummy)
{
	struct cldc_host *dr;
	struct cldc_call_opts copts = { .cb = cb_new_sess };
	char tcode = TC_FAILED;
	struct pollfd pfd[2];
	time_t next_timeout;

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

	thr_udp->sess->verbose = cldcli_verbose;

	pfd[0].fd = thr_udp->fd;
	pfd[0].events = POLLIN;

	pfd[1].fd = to_thread[0];
	pfd[1].events = POLLIN;

	next_timeout = timers_run();

	while (thread_running) {
		int i, rc;

		/* zero revents.  necessary??? */
		for (i = 0; i < ARRAY_SIZE(pfd); i++)
			pfd[i].revents = 0;

		/* poll for activity */
		rc = poll(pfd, 2,
			  next_timeout ? (next_timeout * 1000) : -1);
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

		next_timeout = timers_run();
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

static void cmd_cd(const char *arg)
{
	struct creq creq;
	struct cresp cresp;

	if (!*arg)
		arg = "/";

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
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

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
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

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
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
	if (!mem) {
		fprintf(stderr, "%s: OOM (%u)\n", __func__, (unsigned int) len);
		return;
	}

	/* read file data from thread */
	read_from_thread(mem, len);

	/* write file data to stdout */
	(void) fwrite(mem, len, 1, stdout);
	fprintf(stdout, "\n");

	free(mem);
}

static void cmd_list_locks(void)
{
	struct creq creq;
	struct cresp cresp;
	GList *tmp, *content;

	creq.cmd = CREQ_LIST_LOCKS;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "list-locks failed: %s\n", cresp.msg);
		return;
	}

	content = tmp = cresp.u.list;
	while (tmp) {
		char *s;

		s = tmp->data;
		tmp = tmp->next;

		printf("%s", s);

		free(s);
	}

	g_list_free(content);
}

static void cmd_cp_io(const char *cmd, const char *arg, bool read_cld_file)
{
	struct creq creq;
	struct cresp cresp;
	gchar **sv = NULL, *cld_path, *fs_path;
	void *mem = NULL;
	size_t flen = 0;

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	sv = g_strsplit_set(arg, " \t\f\r\n", 2);
	if (!sv || !sv[0] || !sv[1]) {
		fprintf(stderr, "%s: two arguments required\n", cmd);
		goto out;
	}

	if (read_cld_file) {
		creq.cmd = CREQ_CP_CF;
		cld_path = sv[0];
		fs_path = sv[1];
	} else {
		gchar *fs_content = NULL;
		gsize fs_len = 0;

		creq.cmd = CREQ_CP_FC;
		cld_path = sv[1];
		fs_path = sv[0];

		if (!g_file_get_contents(fs_path, &fs_content,
					 &fs_len, NULL)) {
			fprintf(stderr, "Failed to read data from FS path %s\n",
				fs_path);
			goto out;
		}

		mem = fs_content;
		flen = fs_len;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), cld_path)) {
		fprintf(stderr, "%s: path too long\n", arg);
		goto out;
	}

	creq.cfi.mem = mem;
	creq.cfi.mem_len = flen;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s(%s -> %s) failed: %s\n",
			cmd, sv[0], sv[1], cresp.msg);
		goto out;
	}

	if (read_cld_file) {
		flen = cresp.u.file_len;
		mem = malloc(flen);
		if (!mem) {
			fprintf(stderr, "%s: OOM (%u)\n",
				__func__, (unsigned int) flen);
			exit(1);
		}

		read_from_thread(mem, flen);

		if (!g_file_set_contents(fs_path, mem, flen, NULL)) {
			fprintf(stderr, "Successfully read CLD data from %s,\n"
				"but failed to write data to FS path %s\n",
				cld_path,
				fs_path);
		}
	}

out:
	g_strfreev(sv);
	free(mem);
}

static void basic_cmd(const char *cmd, const char *arg, enum creq_cmd cmd_no)
{
	struct creq creq;
	struct cresp cresp;

	if (!*arg) {
		fprintf(stderr, "%s: argument required\n", cmd);
		return;
	}

	if (!make_abs_path(creq.path, sizeof(creq.path), arg)) {
		fprintf(stderr, "%s: path too long\n", arg);
		return;
	}

	creq.cmd = cmd_no;

	/* send message to thread */
	write_to_thread(&creq, sizeof(creq));

	/* wait for and receive response from thread */
	read_from_thread(&cresp, sizeof(cresp));

	if (cresp.tcode != TC_OK) {
		fprintf(stderr, "%s(%s) failed: %s\n", cmd, arg, cresp.msg);
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
		if (!push_host(arg))
			argp_usage(state);
		break;
	case 'u':
		if (strlen(arg) >= CLD_MAX_USERNAME) {
			fprintf(stderr, "invalid user: '%s'\n", arg);
			argp_usage(state);
		} else
			strcpy(our_user, arg);
		break;
	case 'v':
		cldcli_verbose = true;
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

	g_thread_init(NULL);

	cldc_init();

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
		if (cldc_getaddr(&host_list, hostb, debugging, applog)) {
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
			basic_cmd(tok1, tok2, CREQ_RM);
		else if (!strcmp(tok1, "mkdir"))
			basic_cmd(tok1, tok2, CREQ_MKDIR);
		else if (!strcmp(tok1, "cat"))
			cmd_cat(tok2);
		else if (!strcmp(tok1, "cpin"))
			cmd_cp_io(tok1, tok2, false);
		else if (!strcmp(tok1, "cpout"))
			cmd_cp_io(tok1, tok2, true);
		else if (!strcmp(tok1, "lock"))
			basic_cmd(tok1, tok2, CREQ_LOCK);
		else if (!strcmp(tok1, "trylock"))
			basic_cmd(tok1, tok2, CREQ_TRYLOCK);
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

	thread_running = 0;

	return 0;
}


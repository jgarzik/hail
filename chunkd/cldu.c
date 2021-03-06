
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
#include "hail-config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <ncld.h>
#include "chunkd.h"

#define N_CLD		10	/* 5 * (v4+v6) */

struct cld_host {
	int known;
	struct cldc_host h;
};

struct cld_session {
	bool			forced_hosts;	/* Administrator overrode default CLD */
	bool			is_dead;
	struct ncld_sess	*nsess;	/* library state */

	int			actx;		/* Active host cldv[actx] */
	struct cld_host		cldv[N_CLD];

	int			event_pipe[2];
	struct event		ev;
	struct event		ev_timer;
	bool			have_timer;

	char		*ffname;
	struct ncld_fh	*ffh;	/* keep open for lock */
	uint32_t	nid;
	const char	*ourhost;	/* N.B. points to some global data. */
	struct geo	*ploc;	/* N.B. points to some global data. */

	void (*state_cb)(enum st_cld);
};

static int cldu_set_cldc(struct cld_session *cs, int newactive);

struct hail_log cldu_hail_log = {
	.func		= applog,
};

/*
 * Identify the next host to be tried.
 *
 * In theory we should at least look at priorities, if not weights. Maybe later.
 */
static int cldu_nextactive(struct cld_session *cs)
{
	int i;
	int n;

	if ((n = cs->actx + 1) >= N_CLD)
		n = 0;
	for (i = 0; i < N_CLD; i++) {
		if (cs->cldv[n].known)
			return n;
		if (++n >= N_CLD)
			n = 0;
	}
	/* Full circle, end on the old actx */
	return cs->actx;
}

static void cldu_saveargs(struct cld_session *sp, char *infopath,
			  uint32_t thisnid, const char *thishost,
			  struct geo *loc)
{
	sp->ffname = infopath;
	sp->nid = thisnid;
	sp->ourhost = thishost;
	sp->ploc = loc;
}

static void cldu_sess_proc(struct cld_session *cs)
{
	int newactive;

	if (cs->is_dead) {
		/* This would be the perfect time to call cs->state_cb. XXX */

		if (debugging)
			applog(LOG_DEBUG, "Reopening Chunk in %s", cs->ffname);

		if (cs->nsess) {
			ncld_sess_close(cs->nsess);
			cs->nsess = NULL;
		}
		cs->ffh = NULL;			/* closed automatically */
		newactive = cldu_nextactive(cs);
		if (cldu_set_cldc(cs, newactive)) {
			/* Oops, should not happen. Just loop, then... */
			struct timeval tv = { 30, 0 };
			evtimer_add(&cs->ev_timer, &tv);
			cs->have_timer = true;
			return;
		}
		cs->is_dead = false;
	} else {
		/*
		 * We want to see if this ever happens.
		 * Probably harmless, but... let's print it.
		 */
		applog(LOG_WARNING, "Event on non-dead session");
	}
}

static void cldu_timer_event(int fd, short events, void *userdata)
{
	struct cld_session *cs = userdata;

	cldu_sess_proc(cs);
}

static void cldu_pipe_event(int fd, short events, void *userdata)
{
	struct cld_session *cs = userdata;
	unsigned char cmd;
	ssize_t rc;

	rc = read(fd, &cmd, 1);
	if (rc > 0)
		cldu_sess_proc(cs);
	else
		applog(LOG_WARNING, "Stray CLD event pipe poll");
}

static void cldu_sess_event(void *priv, uint32_t what)
{
	struct cld_session *cs = priv;
	unsigned char cmd;

	if (what == CE_SESS_FAILED) {
		/*
		 * In ncld, we are not allowed to free the session structures
		 * from an event (it's wages of all-conquering 100% reliable
		 * ncld_close_sess), so we bounce that off to the main thread.
		 */
		if (cs->nsess) {
			applog(LOG_ERR, "Session failed, sid " SIDFMT,
			       SIDARG(cs->nsess->tcp->sess->sid));
		} else {
			applog(LOG_ERR, "Session open failed");
		}
		cs->is_dead = true;
		cmd = 1;
		if (write(cs->event_pipe[1], &cmd, 1) < 1) {
			applog(LOG_ERR, "Pipe write failed: %d", errno);
		}
	} else {
		if (cs)
			applog(LOG_INFO, "cldc event 0x%x sid " SIDFMT,
			       what, SIDARG(cs->nsess->tcp->sess->sid));
		else
			applog(LOG_INFO, "cldc event 0x%x no sid", what);
	}
}

/*
 * Create the directories: mkdir -p $(dirname $path).
 */
static int cldu_make_path(struct ncld_sess *nsess, const char *path)
{
	const char *compdir;	/* the current component directory */
	const char *compend;	/* the component's end (position of slash) */
	char *dir;
	unsigned int mode;
	struct ncld_fh *dh;
	int error;

	/* Our configurator has this check too, but let's be safe. */
	if (path[0] != '/')
		return -1;
	compdir = path + sizeof('/');

	for (;;) {
		if (!compdir[0]) {
			applog(LOG_ERR, "CLD path (%s) is invalid", path);
			return -1;	/* Path ends with slash - error */
		}
		compend = strchr(compdir, '/');
		if (!compend)		/* It's a file, all done */
			return 0;

		dir = strndup(path, compend - path);	/* always absolute */
		if (!dir) {
			applog(LOG_ERR, "No core (%d)", compend - path);
			return -1;
		}

		mode = COM_READ | COM_WRITE | COM_CREATE | COM_DIRECTORY,
		dh = ncld_open(nsess, dir, mode, &error, 0, NULL, NULL);
		if (!dh) {
			applog(LOG_ERR, "CLD open(%s) failed: %d", dir, error);
			free(dir);
			return -1;
		}

		free(dir);
		ncld_close(dh);

		compdir = compend + 1;
	}
	return 0;
}

/*
 * Create the file with our parameters in memory, return as ret.
 */
static int cldu_make_ffile(char **ret, struct cld_session *cs)
{
	GList *str_list = NULL;
	struct geo *loc = cs->ploc;
	char *buf;
	char *str;
	size_t len;
	struct list_head *tmpsock;
	GList *tmp;
	int rc;

	rc = asprintf(&str,
		      "<Chunk>\r\n"
		      " <NID>%u</NID>\r\n",
		      cs->nid);
	if (rc == -1) {
		applog(LOG_ERR, "OOM in asprintf\n");
		goto error;
	}
	str_list = g_list_append(str_list, str);

	/*
	 * XXX FIXME sockets has to be a parameter, not global
	 */
	list_for_each(tmpsock, &chunkd_srv.sockets) {
		struct server_socket *sock;
		const struct listen_cfg *cfg;
		const char *host;

		sock = list_entry(tmpsock, struct server_socket, sockets_node);
		cfg = sock->cfg;
		host = cfg->node;
		if (host == NULL || host[0] == 0)
			host = cs->ourhost;

		rc = asprintf(&str,
			" <Socket>\r\n"
			"  <Host>%s</Host>\r\n"
			"  <Port>%s</Port>\r\n"
			" </Socket>\r\n",
			host,
			cfg->port);
		if (rc == -1) {
			applog(LOG_ERR, "OOM in asprintf\n");
			goto error;
		}
		str_list = g_list_append(str_list, str);
	}

	rc = asprintf(&str,
		" <Geo>\r\n"
		"  <Area>%s</Area>\r\n"
		"  <Building>%s</Building>\r\n"
		"  <Rack>%s</Rack>\r\n"
		" </Geo>\r\n"
		"</Chunk>\r\n",
		loc->area ? loc->area : "-",
		loc->zone ? loc->zone : "-",
		loc->rack ? loc->rack : "-");
	if (rc == -1) {
		applog(LOG_ERR, "OOM in asprintf\n");
		goto error;
	}
	str_list = g_list_append(str_list, str);

	len = 0;
	for (tmp = str_list; tmp; tmp = tmp->next)
		len += strlen(tmp->data);
	len++;		// nul

	buf = malloc(len);
	if (!buf) {
		applog(LOG_ERR, "OOM for ffile");
		rc = -1;
		goto error;
	}

	len = 0;
	for (tmp = str_list; tmp; tmp = tmp->next) {
		strcpy(buf + len, tmp->data);
		len += strlen(tmp->data);
	}
	buf[len] = 0;

	*ret = buf;
	rc = 0;
error:
	for (tmp = str_list; tmp; tmp = tmp->next)
		free(tmp->data);
	g_list_free(str_list);
	return rc;
}

/*
 * Open the library and start its session.
 * Our session remains consistent in case of an error in this function,
 * so that we can continue and retry meaningfuly.
 */
static int cldu_set_cldc(struct cld_session *cs, int newactive)
{
	struct cldc_host *hp;
	struct timespec tm;
	char *buf = NULL; /* stupid gcc 4.4.1 throws a warning */
	int len;
	int error;
	int rc;

	if (cs->nsess) {
		ncld_sess_close(cs->nsess);
		cs->nsess = NULL;
	}

	cs->actx = newactive;
	if (!cs->cldv[cs->actx].known) {
		applog(LOG_ERR, "No CLD hosts");
		goto err_addr;
	}
	hp = &cs->cldv[cs->actx].h;

	if (debugging)
		applog(LOG_INFO, "Selected CLD host %s port %u",
		       hp->host, hp->port);

	cs->nsess = ncld_sess_open(hp->host, hp->port, &error,
				   cldu_sess_event, cs, "tabled", "tabled",
				   &cldu_hail_log);
	if (cs->nsess == NULL) {
		if (error < 1000) {
			applog(LOG_ERR, "ncld_sess_open(%s,%u) error: %s",
			       hp->host, hp->port, strerror(error));
		} else {
			applog(LOG_ERR, "ncld_sess_open(%s,%u) error: %d",
			       hp->host, hp->port, error);
		}
		goto err_nsess;
	}

	applog(LOG_INFO, "New CLD session created, sid " SIDFMT,
	       SIDARG(cs->nsess->tcp->sess->sid));

	/*
	 * First, make sure the base directory exists.
	 */
	if (cldu_make_path(cs->nsess, cs->ffname))
		goto err_path;

	/*
	 * Path done, create the membership file for us, keep it open.
	 *
	 * It is a bit racy to create a file like this, applications can see
	 * an empty file, or a file with stale contents. But what to do?
	 */
	cs->ffh = ncld_open(cs->nsess, cs->ffname,
			    COM_WRITE | COM_LOCK | COM_CREATE,
			    &error, 0 /* CE_MASTER_FAILOVER | CE_SESS_FAILED */,
			    NULL, NULL);
	if (cs->ffh == NULL) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", cs->ffname, error);
		goto err_fopen;
	}

	if (debugging)
		applog(LOG_DEBUG, "CLD file \"%s\" created", cs->ffname);

	/*
	 * Lock the file, in case two hosts got the same NID.
	 */
	for (;;) {
		rc = ncld_trylock(cs->ffh);
		if (!rc)
			break;

		applog(LOG_ERR, "CLD lock(%s) failed: %d", cs->ffname, rc);
		if (rc != CLE_LOCK_CONFLICT + 1100)
			goto err_lock;

		/*
		 * The usual reason why we get a lock conflict is
		 * restarting too quickly and hitting the previous lock
		 * that is going to disappear soon.
		 */
		tm.tv_sec = 10;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);
	}

	if (cldu_make_ffile(&buf, cs))
		goto err_buf;
	len = strlen(buf);

	rc = ncld_write(cs->ffh, buf, len);
	if (rc) {
		applog(LOG_ERR, "CLD put(%s) failed: %d", cs->ffname, rc);
		goto err_write;
	}

	free(buf);

	if (debugging)
		applog(LOG_DEBUG, "CLD file \"%s\" written", cs->ffname);

	/*
	 * At this point we just hang here with cs->ffh open and locked
	 * until session fails or we shut down completely.
	 */
	return 0;

err_write:
err_buf:
err_lock:
	ncld_close(cs->ffh);	/* session-close closes these, maybe drop */
err_fopen:
err_path:
	ncld_sess_close(cs->nsess);
	cs->nsess = NULL;
err_nsess:
err_addr:
	return -1;
}

/*
 */
static struct cld_session ses;

/*
 * Global and 1-instance initialization.
 */
void cld_init()
{
	ncld_init();
}

/*
 * This initiates our sole session with a CLD instance.
 *
 * Mostly due to our laziness and lack of need, thishost and locp are saved
 * by reference, so their lifetime must exceed the lifetime of the session
 * (the time between cld_begin and cld_end).
 */
int cld_begin(const char *thishost, uint32_t nid, char *infopath,
	      struct geo *locp, void (*cb)(enum st_cld))
{
	static struct cld_session *cs = &ses;
	int rfd;
	int retry_cnt;
	int newactive;

	if (!nid)
		return 0;

	/*
	 * As long as we permit pre-seeding lists of CLD hosts,
	 * we cannot wipe our session anymore. Note though, as long
	 * as cld_end terminates it right, we can call cld_begin again.
	 */
	// memset(&ses, 0, sizeof(struct cld_session));
	cs->state_cb = cb;

	evtimer_set(&cs->ev_timer, cldu_timer_event, cs);

	cldu_saveargs(cs, infopath, nid, thishost, locp);

	if (!cs->forced_hosts) {
		GList *tmp, *host_list = NULL;
		int i;

		if (cldc_getaddr(&host_list, thishost, &cldu_hail_log)) {
			/* Already logged error */
			goto err_addr;
		}

		/* copy host_list into cld_session host array,
		 * taking ownership of alloc'd strings along the way
		 */
		i = 0;
		for (tmp = host_list; tmp; tmp = tmp->next) {
			struct cldc_host *hp = tmp->data;
			if (i < N_CLD) {
				memcpy(&cs->cldv[i].h, hp,
				       sizeof(struct cldc_host));
				cs->cldv[i].known = 1;
				i++;
			} else {
				free(hp->host);
			}
			free(hp);
		}

		g_list_free(host_list);
	}

	if (pipe(cs->event_pipe) < 0) {
		applog(LOG_ERR, "Cannot open pipe: %s", strerror(errno));
		goto err_pipe;
	}
	rfd = cs->event_pipe[0];

	event_set(&cs->ev, rfd, EV_READ | EV_PERSIST, cldu_pipe_event, cs);

	if (event_add(&cs->ev, NULL) < 0) {
		applog(LOG_ERR, "event_add cldu fail");
		goto err_sp;
	}

	/*
	 * FIXME: We should find next suitable host according to
	 * the priority and weight (among those which are up).
	 * -- Actually, it only works when recovering from CLD failure.
	 *    Thereafter, any slave CLD redirects us to the master.
	 */
	newactive = 0;
	retry_cnt = 0;
	for (;;) {
		if (!cldu_set_cldc(cs, newactive))
			break;
		/* Already logged error */
		if (++retry_cnt == 5)
			goto err_net;
		newactive = cldu_nextactive(cs);
	}

	return 0;

err_net:
	event_del(&cs->ev);
err_sp:
	close(cs->event_pipe[0]);
	close(cs->event_pipe[1]);
err_pipe:
err_addr:
	return -1;
}

void cldu_add_host(const char *hostname, unsigned int port)
{
	static struct cld_session *cs = &ses;
	struct cld_host *hp;
	int i;

	for (i = 0; i < N_CLD; i++) {
		hp = &cs->cldv[i];
		if (!hp->known)
			break;
	}
	if (i >= N_CLD)
		return;

	if (cldc_saveaddr(&hp->h, 100, 100, port, strlen(hostname), hostname,
			  &cldu_hail_log))
		return;
	hp->known = 1;

	cs->forced_hosts = true;
}

void cld_end(void)
{
	static struct cld_session *cs = &ses;
	int i;

	if (!cs->nid)
		return;

	if (cs->have_timer) {
		evtimer_del(&cs->ev_timer);
		cs->have_timer = false;
	}

	if (cs->nsess) {
		ncld_sess_close(cs->nsess);
		cs->nsess = NULL;
	}

	if (!cs->forced_hosts) {
		for (i = 0; i < N_CLD; i++) {
			if (cs->cldv[i].known) {
				free(cs->cldv[i].h.host);
				cs->cldv[i].known = false;
			}
		}
	}

	event_del(&cs->ev);
	close(cs->event_pipe[0]);
	close(cs->event_pipe[1]);

	free(cs->ffname);
	cs->ffname = NULL;
}


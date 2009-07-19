/*
 * Copyright (c) 2009, Red Hat, Inc.
 */
#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <cldc.h>
#include "chunkd.h"

#define ALIGN8(n)	((8 - ((n) & 7)) & 7)

#define N_CLD		10	/* 5 * (v4+v6) */

struct cld_host {
	int known;
	unsigned int prio;
	unsigned int weight;
	char *host;
	unsigned short port;
};

struct cld_session {
	bool forced_hosts;		/* Administrator overrode default CLD */
	bool sess_open;
	struct cldc_udp *lib;		/* library state */

	int actx;		/* Active host cldv[actx] */
	struct cld_host cldv[N_CLD];

	struct event ev;	/* Associated with fd */
	char *cfname;		/* /chunk-CELL directory */
	struct cldc_fh *cfh;	/* /chunk-CELL directory fh */
	char *ffname;		/* /chunk-CELL/NID */
	struct cldc_fh *ffh;	/* /chunk-cell/NID, keep open for lock */
	uint32_t nid;
	struct geo *ploc;	/* N.B. points to some global data. */

	void (*state_cb)(enum st_cld);
};

static int cldu_set_cldc(struct cld_session *sp, int newactive);
static int cldu_new_sess(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_open_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_close_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_open_f_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_lock_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_put_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);

#define SVC "chunk"
static char svc[] = SVC;

/* The format comes with a trailing newline, but fortunately syslog strips it */
void cldu_p_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

/*
 * Identify the next host to be tried.
 *
 * In theory we should at least look at priorities, if not weights. Maybe later.
 */
static int cldu_nextactive(struct cld_session *sp)
{
	int i;
	int n;

	if ((n = sp->actx + 1) >= N_CLD)
		n = 0;
	for (i = 0; i < N_CLD; i++) {
		if (sp->cldv[n].known)
			return n;
		if (++n >= N_CLD)
			n = 0;
	}
	/* Full circle, end on the old actx */
	return n;
}

static int cldu_setcell(struct cld_session *sp,
			const char *thiscell, uint32_t thisnid, struct geo *locp)
{
	size_t cnlen;
	size_t mlen;
	char nbuf[11];	/* 32 bits in decimal and nul */
	char *mem;

	if (thiscell == NULL) {
		thiscell = "default";
	}

	snprintf(nbuf, 11, "%u", thisnid);

	cnlen = strlen(thiscell);

	mlen = sizeof("/" SVC "-")-1;
	mlen += cnlen;
	mlen++;	// '\0'
	mem = malloc(mlen);
	sprintf(mem, "/%s-%s", svc, thiscell);
	sp->cfname = mem;

	mlen = sizeof("/" SVC "-")-1;
	mlen += cnlen;
	mlen++;	// '/'
	mlen += strlen(nbuf);
	mlen++;	// '\0'
	mem = malloc(mlen);
	sprintf(mem, "/%s-%s/%s", svc, thiscell, nbuf);
	sp->ffname = mem;

	sp->nid = thisnid;
	sp->ploc = locp;

	return 0;
}

/*
 * Helper: Look up the host to verify it, then save the parameters into
 * our struct (*hp). This way the application quits early if DNS is set wrong.
 */
static int cldu_saveaddr(struct cld_host *hp, unsigned int priority,
			 unsigned int weight, unsigned int port,
			 unsigned int nlen, const char *name)
{
	char portstr[11];
	char *hostname;
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	bool something_suitable;
	int rc;

	sprintf(portstr, "%u", port);

	hostname = malloc(nlen + 1);
	if (!hostname) {
		rc = -ENOMEM;
		goto err_name;
	}
	memcpy(hostname, name, nlen);
	hostname[nlen] = 0;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(hostname, portstr, &hints, &res0);
	if (rc) {
		syslog(LOG_ERR, "getaddrinfo(%s,%s) failed: %s",
		       hostname, portstr, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

	something_suitable = false;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		something_suitable = true;
		break;
	}

	if (!something_suitable) {
		syslog(LOG_ERR, "Host %s port %u has no addresses",
		       hostname, port);
		rc = -EINVAL;
		goto err_suitable;
	}

	hp->host = hostname;
	hp->port = port;
	hp->prio = priority;
	hp->weight = weight;

	if (debugging) {
		syslog(LOG_INFO,
		       "Found CLD host %s prio %d weight %d",
		       hostname, priority, weight);
	}

	freeaddrinfo(res0);
	return 0;

err_suitable:
	freeaddrinfo(res0);
err_addr:
	free(hostname);
err_name:
	return rc;
}

/*
 * Apparently, the only viable way to find out the DNS domain is to take
 * the hostname, then lop off the first member. We do not support running
 * on YP-driven networks with nonqualified hostnames (at least for now).
 */
static int cldu_make_fqdn(char *buf, int size, const char *srvname,
    const char *thishost)
{
	char *s;
	int nlen;
	int dlen;

	nlen = strlen(srvname);
	if (nlen >= size-20) {
		syslog(LOG_ERR,
		       "cldc_getaddr: internal error (nlen %d size %d)",
		       nlen, size);
		return -1;
	}

	if (thishost == NULL) {
		syslog(LOG_ERR, "cldc_getaddr: internal error (null hostname)");
		return -1;
	}
	if ((s = strchr(thishost, '.')) == NULL) {
		syslog(LOG_ERR,
		       "cldc_getaddr: hostname is not FQDN: \"%s\"",
		       thishost);
		return -1;
	}
	s++;

	dlen = strlen(s);
	if (nlen + 1 + dlen + 1 > size) {
		syslog(LOG_ERR,
		       "cldc_getaddr: domain is too long: \"%s\"", s);
		return -1;
	}

	memcpy(buf, srvname, nlen);
	buf[nlen] = '.';
	strcpy(buf + nlen + 1, s);

	return 0;
}

/*
 * Fill out hosts vector in the session.
 * Despite taking session pointer like everything else, this is not reentrant.
 * Better be called before any other threads are started.
 */
static int cldu_getaddr(struct cld_session *sp, const char *thishost)
{
	enum { hostsz = 64 };
	char cldb[hostsz];
	unsigned char resp[512];
	int rlen;
	ns_msg nsb;
	ns_rr rrb;
	int rrlen;
	char hostb[hostsz];
	int i;
	struct cld_host *hp;
	int n;
	const unsigned char *p;
	int rc;

	/*
	 * We must create FQDN or else the first thing the resolver does
	 * is a lookup in the DNS root (probably the standard-compliant
	 * dot between "_cld" and "_udp" hurts us here).
	 */
	if (cldu_make_fqdn(cldb, hostsz, "_cld._udp", thishost) != 0)
		return -1;

	rc = res_search(cldb, ns_c_in, ns_t_srv, resp, 512);
	if (rc < 0) {
		switch (h_errno) {
		case HOST_NOT_FOUND:
			syslog(LOG_ERR, "No _cld._udp SRV record");
			return -1;
		case NO_DATA:
			syslog(LOG_ERR, "Cannot find _cld._udp SRV record");
			return -1;
		case NO_RECOVERY:
		case TRY_AGAIN:
		default:
			syslog(LOG_ERR,
			       "cldc_getaddr: res_search error (%d): %s",
			       h_errno, hstrerror(h_errno));
			return -1;
		}
	}
	rlen = rc;

	if (rlen == 0) {
		syslog(LOG_ERR,
		       "cldc_getaddr: res_search returned empty reply");
		return -1;
	}

	if (ns_initparse(resp, rlen, &nsb) < 0) {
		syslog(LOG_ERR,
		       "cldc_getaddr: ns_initparse error");
		return -1;
	}

	n = 0;
	hp = &sp->cldv[0];
	for (i = 0; i < ns_msg_count(nsb, ns_s_an); i++) {
		rc = ns_parserr(&nsb, ns_s_an, i, &rrb);
		if (rc < 0)
			continue;

		if (ns_rr_class(rrb) != ns_c_in)
			continue;

		switch (ns_rr_type(rrb)) {
		case ns_t_srv:
			rrlen = ns_rr_rdlen(rrb);
			if (rrlen < 8) {	/* 2+2+2 and 2 for host */
				if (debugging) {
					syslog(LOG_INFO,
					       "cldc_getaddr: SRV len %d", 
					       rrlen);
				}
				break;
			}
			p = ns_rr_rdata(rrb);
			rc = dn_expand(resp, resp+rlen, p+6, hostb, hostsz);
			if (rc < 0) {
				if (debugging) {
					syslog(LOG_INFO, "cldc_getaddr: "
					       "dn_expand error %d", rc);
				}
				break;
			}
			if (rc < 2) {
				if (debugging) {
					syslog(LOG_INFO, "cldc_getaddr: "
					       "dn_expand short %d", rc);
				}
				break;
			}

			if (n >= N_CLD)
				break;

			if (cldu_saveaddr(hp, ns_get16(p+0), ns_get16(p+2),
					  ns_get16(p+4), rc, hostb))
				break;

			hp->known = 1;
			n++;
			hp++;
			break;
		case ns_t_cname:	/* impossible, but */
			if (debugging) {
				syslog(LOG_INFO,
				       "CNAME in SRV request, ignored");
			}
			break;
		default:
			;
		}
	}

	return 0;
}

static void cldu_event(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;
	int rc;

	if (!sp->lib) {
		syslog(LOG_WARNING, "Stray UDP event");
		return;
	}

	rc = cldc_udp_receive_pkt(sp->lib);
	if (rc) {
		syslog(LOG_INFO, "cldc_udp_receive_pkt failed: %d", rc);
		/*
		 * Reacting to ICMP messages is a bad idea, because
		 *  - it makes us loop hard in case CLD is down, unless we
		 *    insert additional tricky timeouts
		 *  - it deals poorly with transient problems like CLD reboots
		 */
#if 0
		if (rc == -ECONNREFUSED) {	/* ICMP tells us */
			int newactive;
			/* P3 */ syslog(LOG_INFO, "Restarting session");
			// evtimer_del(&sp->tm);
			cldc_kill_sess(sp->lib->sess);
			sp->lib->sess = NULL;
			newactive = cldu_nextactive(sp);
			if (cldu_set_cldc(sp, newactive))
				return;
			// evtimer_add(&sp->tm, &cldc_to_delay);
		}
		return;
#endif
	}
}

static bool cldu_p_timer_ctl(void *priv, bool add,
			     int (*cb)(struct cldc_session *, void *),
			     void *cb_priv, time_t secs)
{
	struct cld_session *sp = priv;
	return cldc_levent_timer(sp->lib, add, cb, cb_priv, secs);
}

static int cldu_p_pkt_send(void *priv, const void *addr, size_t addrlen,
			       const void *buf, size_t buflen)
{
	struct cld_session *sp = priv;
	return cldc_udp_pkt_send(sp->lib, addr, addrlen, buf, buflen);
}

static void cldu_p_event(void *priv, struct cldc_session *csp,
			 struct cldc_fh *fh, uint32_t what)
{
	struct cld_session *sp = priv;
	int newactive;

	if (what == CE_SESS_FAILED) {
		sp->sess_open = false;
		if (sp->lib->sess != csp)
			syslog(LOG_ERR, "Stray session failed, sid " SIDFMT,
			       SIDARG(csp->sid));
		else
			syslog(LOG_ERR, "Session failed, sid " SIDFMT,
			       SIDARG(csp->sid));
		// evtimer_del(&sp->tm);
		sp->lib->sess = NULL;
		newactive = cldu_nextactive(sp);
		if (cldu_set_cldc(sp, newactive))
			return;
		// evtimer_add(&sp->tm, &cldc_to_delay);
	} else {
		if (csp)
			syslog(LOG_INFO, "cldc event 0x%x sid " SIDFMT,
			       what, SIDARG(csp->sid));
		else
			syslog(LOG_INFO, "cldc event 0x%x no sid", what);
	}
}

static struct cldc_ops cld_ops = {
	.timer_ctl =	cldu_p_timer_ctl,
	.pkt_send =	cldu_p_pkt_send,
	.event =	cldu_p_event,
	.printf =	cldu_p_log,
};

/*
 * Open the library, start its session, and reguster its socket with libevent.
 * Our session remains consistent in case of an error in this function,
 * so that we can continue and retry meaningfuly.
 */
static int cldu_set_cldc(struct cld_session *sp, int newactive)
{
	struct cld_host *hp;
	struct cldc_udp *lib;
	struct cldc_call_opts copts;
	int rc;

	if (sp->lib) {
		event_del(&sp->ev);
		cldc_udp_free(sp->lib);
		sp->lib = NULL;
	}

	sp->actx = newactive;
	hp = &sp->cldv[sp->actx];
	if (!hp->known) {
		syslog(LOG_ERR, "No CLD hosts");
		goto err_addr;
	}

	rc = cldc_udp_new(hp->host, hp->port, &sp->lib);
	if (rc) {
		syslog(LOG_ERR, "cldc_udp_new(%s,%u) error: %d",
		       hp->host, hp->port, rc);
		goto err_lib_new;
	}
	lib = sp->lib;

	if (debugging)
		syslog(LOG_INFO, "Selected CLD host %s port %u",
		       hp->host, hp->port);

	/*
	 * This is a little iffy: we assume that it's ok to re-issue
	 * event_set() for an event that was unregistered with event_del().
	 * In any case, there's no other way to set the file descriptor.
	 */
	event_set(&sp->ev, sp->lib->fd, EV_READ | EV_PERSIST, cldu_event, sp);

	if (event_add(&sp->ev, NULL) < 0) {
		syslog(LOG_INFO, "Failed to add CLD event");
		goto err_event;
	}

	memset(&copts, 0, sizeof(struct cldc_call_opts));
	copts.cb = cldu_new_sess;
	copts.private = sp;
	rc = cldc_new_sess(&cld_ops, &copts, lib->addr, lib->addr_len,
			   "tabled", "tabled", sp, &lib->sess);
	if (rc) {
		syslog(LOG_INFO,
		       "Failed to start CLD session on host %s port %u",
		       hp->host, hp->port);
		goto err_sess;
	}

	// if (debugging)
	//	lib->sess->verbose = true;

	return 0;

err_sess:
err_event:
	cldc_udp_free(sp->lib);
	sp->lib = NULL;
err_lib_new:
err_addr:
	return -1;
}

static int cldu_new_sess(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		syslog(LOG_INFO, "New CLD session creation failed: %d", errc);
		return 0;
	}

	sp->sess_open = true;
	syslog(LOG_INFO, "New CLD session created, sid " SIDFMT,
	       SIDARG(sp->lib->sess->sid));

	/*
	 * First, make sure the base directory exists.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_c_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->cfname,
		       COM_READ | COM_WRITE | COM_CREATE | COM_DIRECTORY,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->cfh);
	if (rc) {
		syslog(LOG_ERR, "cldc_open(%s) call error: %d\n",
		       sp->cfname, rc);
	}
	return 0;
}

static int cldu_open_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		syslog(LOG_ERR, "CLD open(%s) failed: %d", sp->cfname, errc);
		return 0;
	}
	if (sp->cfh == NULL) {
		syslog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->cfname);
		return 0;
	}
	if (!sp->cfh->valid) {
		syslog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->cfname);
		return 0;
	}

	if (debugging)
		syslog(LOG_DEBUG, "CLD directory \"%s\" created", sp->cfname);

	/*
	 * We don't use directory handle to open files in it, so close it.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_close_c_cb;
	copts.private = sp;
	rc = cldc_close(sp->cfh, &copts);
	if (rc) {
		syslog(LOG_ERR, "cldc_close call error %d", rc);
	}

	return 0;
}

static int cldu_close_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		syslog(LOG_ERR, "CLD close(%s) failed: %d", sp->cfname, errc);
		return 0;
	}

	/*
	 * Then, create the membership file for us.
	 *
	 * It is a bit racy to create a file like this, applications can see
	 * an empty file, or a file with stale contents. But what to do?
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_f_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->ffname,
		       COM_WRITE | COM_LOCK | COM_CREATE,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->ffh);
	if (rc) {
		syslog(LOG_ERR, "cldc_open(%s) call error: %d\n",
		       sp->ffname, rc);
	}
	return 0;
}

static int cldu_open_f_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		syslog(LOG_ERR, "CLD open(%s) failed: %d", sp->ffname, errc);
		return 0;
	}
	if (sp->ffh == NULL) {
		syslog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->ffname);
		return 0;
	}
	if (!sp->ffh->valid) {
		syslog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->ffname);
		return 0;
	}

	if (debugging)
		syslog(LOG_DEBUG, "CLD file \"%s\" created", sp->ffname);

	/*
	 * Lock the file, in case two hosts got the same NID.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_lock_cb;
	copts.private = sp;
	rc = cldc_lock(sp->ffh, &copts, 0, false);
	if (rc) {
		syslog(LOG_ERR, "cldc_lock call error %d", rc);
	}

	return 0;
}

static int cldu_lock_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	char *bufv[12];
	int i, n;
	char *buf;
	int len;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		syslog(LOG_ERR, "CLD lock(%s) failed: %d", sp->cfname, errc);
		return 0;
	}

	/*
	 * Write the file with our parameters.
	 * We skip <NID> for now, it's in the filename anyhow.
	 */
	n = 0;
	bufv[n++] = "<Geo>\r\n";
	bufv[n++] = "<Area>";
	bufv[n++] = (sp->ploc->area) ? sp->ploc->area : "-";
	bufv[n++] = "</Area>\r\n";
	bufv[n++] = "<Building>";
	bufv[n++] = (sp->ploc->zone) ? sp->ploc->zone : "-";
	bufv[n++] = "</Building>\r\n";
	bufv[n++] = "<Rack>";
	bufv[n++] = (sp->ploc->rack) ? sp->ploc->rack : "-";
	bufv[n++] = "</Rack>\r\n";
	bufv[n++] = "</Geo>\r\n";
	// bufv[n] = NULL;

	len = 0;
	for (i = 0; i < n; i++)
		len += strlen(bufv[i]);
	len++;		// nul

	buf = malloc(len);
	if (!buf) {
		syslog(LOG_ERR, "No core for NID file");
		return 0;
	}

	len = 0;
	for (i = 0; i < n; i++) {
		strcpy(buf + len, bufv[i]);
		len += strlen(bufv[i]);
	}
	buf[len] = 0;

	if (debugging)
		syslog(LOG_DEBUG, "Writing CLD file (%s): %s", sp->ffname, buf);

	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_put_cb;
	copts.private = sp;
	rc = cldc_put(sp->ffh, &copts, buf, len);
	if (rc) {
		syslog(LOG_ERR, "cldc_put(%s) call error: %d\n",
		       sp->ffname, rc);
	}

	free(buf);

	return 0;
}

static int cldu_put_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	// struct cldc_call_opts copts;
	// int rc;

	if (errc != CLE_OK) {
		syslog(LOG_ERR, "CLD put(%s) failed: %d", sp->ffname, errc);
		return 0;
	}

	return 0;
}

/*
 */
static struct cld_session ses;

/*
 * This initiates our sole session with a CLD instance.
 */
int cld_begin(const char *thishost, const char *thiscell, uint32_t nid,
	      struct geo *locp, void (*cb)(enum st_cld))
{

	/*
	 * As long as we permit pre-seeding lists of CLD hosts,
	 * we cannot wipe our session anymore. Note though, as long
	 * as cld_end terminates it right, we can call cld_begin again.
	 */
	// memset(&ses, 0, sizeof(struct cld_session));
	ses.state_cb = cb;

	if (cldu_setcell(&ses, thiscell, nid, locp)) {
		/* Already logged error */
		goto err_cell;
	}

	if (!ses.forced_hosts) {
		if (cldu_getaddr(&ses, thishost)) {
			/* Already logged error */
			goto err_addr;
		}
	}

	/*
	 * FIXME: We should find next suitable host according to
	 * the priority and weight (among those which are up).
	 * -- Actually, it only works when recovering from CLD failure.
	 *    Thereafter, any slave CLD redirects us to the master.
	 */
	if (cldu_set_cldc(&ses, 0)) {
		/* Already logged error */
		goto err_net;
	}

	return 0;

err_net:
err_addr:
err_cell:
	return -1;
}

void cld_end(void)
{
	int i;

	if (ses.lib) {
		event_del(&ses.ev);
		// if (ses.sess_open)	/* kill it always, include half-open */
		cldc_kill_sess(ses.lib->sess);
		cldc_udp_free(ses.lib);
		ses.lib = NULL;
	}

	if (!ses.forced_hosts) {
		for (i = 0; i < N_CLD; i++) {
			if (ses.cldv[i].known)
				free(ses.cldv[i].host);
		}
	}

	free(ses.cfname);
	free(ses.ffname);
}

void cldu_add_host(const char *hostname, unsigned int port)
{
	static struct cld_session *sp = &ses;
	struct cld_host *hp;
	int i;

	for (i = 0; i < N_CLD; i++) {
		hp = &sp->cldv[i];
		if (!hp->known)
			break;
	}
	if (i >= N_CLD)
		return;

	if (cldu_saveaddr(hp, 100, 100, port, strlen(hostname), hostname))
		return;
	hp->known = 1;

	sp->forced_hosts = true;
}

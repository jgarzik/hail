
/*
 * Create a file in CLD.
 */
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cldc.h>
#include <libtimer.h>
#include "test.h"

#define DATAMAX  10000

struct run {
	struct cldc_udp *udp;
	struct timer tmr_udp;
	struct cldc_fh *fh;
	char *fname;
	char *buf;
	int len;
};

static int new_sess_cb(struct cldc_call_opts *copts, enum cle_err_codes errc);
static int open_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static int write_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static void call_close(struct run *rp);
static int close_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static int end_sess_cb(struct cldc_call_opts *copts, enum cle_err_codes errc);

static bool do_timer_ctl(void *priv, bool add,
			 int (*cb)(struct cldc_session *, void *),
			 void *cb_priv, time_t secs)
{
	struct run *rp = priv;

	if (add) {
		rp->udp->cb = cb;
		rp->udp->cb_private = cb_priv;
		timer_add(&rp->tmr_udp, time(NULL) + secs);
	} else {
		timer_del(&rp->tmr_udp);
	}
	return true;
}

static int do_pkt_send(void *priv, const void *addr, size_t addrlen,
		       const void *buf, size_t buflen)
{
	struct run *rp = priv;
	return cldc_udp_pkt_send(rp->udp, addr, addrlen, buf, buflen);
}

static void timer_udp_event(struct timer *timer)
{
	struct run *rp = timer->userdata;
	struct cldc_udp *udp;

	udp = rp->udp;
	if (udp->cb)
		udp->cb(udp->sess, udp->cb_private);
}

static void do_event(void *private, struct cldc_session *sess,
		     struct cldc_fh *fh, uint32_t event_mask)
{
	fprintf(stderr, "EVENT(0x%x)\n", event_mask);
}

static int new_sess_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "new-sess failed: %d\n", errc);
		exit(1);
	}

	/* We use a fixed file name because we contact a private copy of CLD */
	memset(&copts, 0, sizeof(copts));
	copts.cb = open_1_cb;
	copts.private = rp;
	rc = cldc_open(rp->udp->sess, &copts, rp->fname,
		       COM_WRITE | COM_CREATE,
		       CE_SESS_FAILED, &rp->fh);
	if (rc) {
		fprintf(stderr, "cldc_open call error %d\n", rc);
		exit(1);
	}
	return 0;
}

static int open_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "first-open failed: %d\n", errc);
		exit(1);
	}
	if (rp->fh == NULL) {
		fprintf(stderr, "first-open NULL fh\n");
		exit(1);
	}
	if (!rp->fh->valid) {
		fprintf(stderr, "first-open invalid fh\n");
		exit(1);
	}

	if (rp->len == 0) {
		call_close(rp);
	} else {
		memset(&copts, 0, sizeof(copts));
		copts.cb = write_1_cb;
		copts.private = rp;
		rc = cldc_put(rp->fh, &copts, rp->buf, rp->len);
		if (rc) {
			fprintf(stderr, "cldc_put call error %d for %d bytes\n",
				rc, rp->len);
			exit(1);
		}
	}
	return 0;
}

static int write_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;

	if (errc != CLE_OK) {
		fprintf(stderr, "first-put failed: %d\n", errc);
		exit(1);
	}

	call_close(rp);
	return 0;
}

static void call_close(struct run *rp)
{
	struct cldc_call_opts copts;
	int rc;

	memset(&copts, 0, sizeof(copts));
	copts.cb = close_1_cb;
	copts.private = rp;
	rc = cldc_close(rp->fh, &copts);
	if (rc) {
		fprintf(stderr, "cldc_close call error %d\n", rc);
		exit(1);
	}
}

static int close_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "first-close failed: %d\n", errc);
		exit(1);
	}
	rp->fh = NULL;

	memset(&copts, 0, sizeof(copts));
	copts.cb = end_sess_cb;
	copts.private = rp;
	rc = cldc_end_sess(rp->udp->sess, &copts);
	if (rc) {
		fprintf(stderr, "cldc_end_sess call error %d\n", rc);
		exit(1);
	}
	return 0;
}

static int end_sess_cb(struct cldc_call_opts *copts, enum cle_err_codes errc)
{
	if (errc != CLE_OK) {
		fprintf(stderr, "end-sess failed: %d\n", errc);
		exit(1);
	}

	/* session ended; success */
	exit(0);
	return 0;
}

static struct run run;

static struct cldc_ops ops = {
	.timer_ctl		= do_timer_ctl,
	.pkt_send		= do_pkt_send,
	.event			= do_event,
};

static int init(char *name)
{
	int rc;
	int port;
	struct cldc_call_opts copts;

	run.fname = name;
	run.buf = TESTSTR;
	run.len = TESTLEN;

	port = cld_readport(TEST_PORTFILE_CLD);
	if (port < 0)
		return port;
	if (port == 0)
		return -1;

	timer_init(&run.tmr_udp, "udp-timer", timer_udp_event, &run);

	rc = cldc_udp_new(TEST_HOST, port, &run.udp);
	if (rc)
		return rc;

	memset(&copts, 0, sizeof(copts));
	copts.cb = new_sess_cb;
	copts.private = &run;
	rc = cldc_new_sess(&ops, &copts, run.udp->addr, run.udp->addr_len,
			   TEST_USER, TEST_USER_KEY, &run, &run.udp->sess);
	if (rc)
		return rc;

	// run.udp->sess->verbose = true;

	return 0;
}

int main(int argc, char *argv[])
{
	g_thread_init(NULL);
	cldc_init();
	if (init(TFNAME))
		return 1;
	test_loop(run.udp);
	return 0;
}


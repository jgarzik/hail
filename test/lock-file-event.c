
/*
 * Create a file in CLD, lock it.
 * This version uses libevent.
 */
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <event.h>
#include <cldc.h>

#define TESTSTR          "testlock\n"
#define TESTLEN  (sizeof("testlock\n")-1)

struct run {
	struct cldc_udp *udp;
	struct event udp_ev;
	struct event tmr_ev;
	struct cldc_fh *fh;
	char buf[TESTLEN];
};

static int new_sess_cb(struct cldc_call_opts *copts, enum cle_err_codes errc);
static int open_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static int write_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static int lock_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static void timer_1(int fd, short events, void *userdata);
static int close_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc);
static int end_sess_cb(struct cldc_call_opts *copts, enum cle_err_codes errc);

static void do_event(void *private, struct cldc_session *sess,
		     struct cldc_fh *fh, uint32_t event_mask)
{
	fprintf(stderr, "EVENT(0x%x)\n", event_mask);
}

static void udp_event(int fd, short events, void *userdata)
{
	struct run *rp = userdata;
	int rc;

	rc = cldc_udp_receive_pkt(rp->udp);
	if (rc) {
		fprintf(stderr, "cldc_udp_receive_pkt failed: %d\n", rc);
		exit(1);
	}
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
	rc = cldc_open(rp->udp->sess, &copts, "/cld-lock-inst",
		       COM_WRITE | COM_LOCK | COM_CREATE,
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

	memset(&copts, 0, sizeof(copts));
	copts.cb = write_1_cb;
	copts.private = rp;
	rc = cldc_put(rp->fh, &copts, rp->buf, TESTLEN);
	if (rc) {
		fprintf(stderr, "cldc_put call error %d\n", rc);
		exit(1);
	}
	return 0;
}

static int write_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "first-put failed: %d\n", errc);
		exit(1);
	}

	memset(&copts, 0, sizeof(copts));
	copts.cb = lock_1_cb;
	copts.private = rp;
	rc = cldc_lock(rp->fh, &copts, 0, false);
	if (rc) {
		fprintf(stderr, "cldc_lock call error %d\n", rc);
		exit(1);
	}
	return 0;
}

static int lock_1_cb(struct cldc_call_opts *coptarg, enum cle_err_codes errc)
{
	struct run *rp = coptarg->private;
	struct timeval tv = { 40, 0 };	/* 40s to make sure session sustains */
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "first-lock failed: %d\n", errc);
		exit(1);
	}

	rc = evtimer_add(&rp->tmr_ev, &tv);
	if (rc) {
		fprintf(stderr, "evtimer_add call error %d\n", rc);
		exit(1);
	}
	return 0;
}

static void timer_1(int fd, short events, void *userdata)
{
	struct run *rp = userdata;
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
	event_loopbreak();

	return 0;
}

static struct run run;

static struct cldc_ops ops = {
	.timer_ctl		= cldc_levent_timer,
	.pkt_send		= cldc_udp_pkt_send,
	.event			= do_event,
};

static int init(void)
{
	int rc;
	struct cldc_call_opts copts;

	memcpy(run.buf, TESTSTR, TESTLEN);

	rc = cldc_udp_new("localhost", 18181, &run.udp);
	if (rc)
		return rc;

	memset(&copts, 0, sizeof(copts));
	copts.cb = new_sess_cb;
	copts.private = &run;
	rc = cldc_new_sess(&ops, &copts, run.udp->addr, run.udp->addr_len,
			   "testuser", "testuser", run.udp, &run.udp->sess);
	if (rc)
		return rc;

	// run.udp->sess->verbose = true;

	event_set(&run.udp_ev, run.udp->fd, EV_READ | EV_PERSIST,
		  udp_event, &run);
	evtimer_set(&run.tmr_ev, timer_1, &run);

	if (event_add(&run.udp_ev, NULL) < 0) {
		fprintf(stderr, "event_add failed\n");
		return 1;
	}

	return 0;
}

int main (int argc, char *argv[])
{
	srand(time(NULL) ^ getpid());
	event_init();
	if (init())
		return 1;
	event_dispatch();
	return 0;
}


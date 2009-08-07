
/*
 * Create a file in CLD.
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

#define TESTSTR          "longertestdata\n"
#define TESTLEN  (sizeof("longertestdata\n")-1)

#define TFNAME     "/cld-test-inst"

#define DATAMAX  10000

struct run {
	struct cldc_udp *udp;
	struct event udp_ev;
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
	event_loopbreak();

	return 0;
}

static struct run run;
#if 0
static char databuf[DATAMAX];
#endif

static struct cldc_ops ops = {
	.timer_ctl		= cldc_levent_timer,
	.pkt_send		= cldc_udp_pkt_send,
	.event			= do_event,
};

static int init(char *name)
{
	int rc;
	struct cldc_call_opts copts;

	run.fname = name;
#if 0
	run.buf = databuf;

	rc = read(0, databuf, DATAMAX);
	if (rc < 0) {
		fprintf(stderr, "read error: %s\n", strerror(errno));
		return -1;
	}
	run.len = rc;
#else
	run.buf = TESTSTR;
	run.len = TESTLEN;
#endif

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

	if (event_add(&run.udp_ev, NULL) < 0) {
		fprintf(stderr, "event_add failed\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	srand(time(NULL) ^ getpid());

#if 0
	if (argc != 2) {
		fprintf(stderr, "Usage: save-file-event {filename}\n");
		return 1;
	}
#endif

	event_init();
#if 0
	if (init(argv[1]))
		return 1;
#else
	if (init(TFNAME))
		return 1;
#endif
	event_dispatch();
	return 0;
}


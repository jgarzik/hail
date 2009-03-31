
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cldc.h>

static struct cldc_udp *udp;
static struct event udp_ev;
static int final_rc;

static void do_event(void *private, struct cldc_session *sess,
		     struct cldc_fh *fh, uint32_t event_mask)
{
	fprintf(stderr, "EVENT(%x)\n", event_mask);
}

static void udp_event(int fd, short events, void *userdata)
{
	int rc;

	rc = cldc_udp_receive_pkt(udp);
	if (rc) {
		fprintf(stderr, "cldc_udp_receive_pkt failed: %d\n", rc);
		exit(1);
	}
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

static int new_sess_cb(struct cldc_call_opts *copts_in, enum cle_err_codes errc)
{
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		fprintf(stderr, "new-sess failed: %d\n", errc);
		exit(1);
	}

	memset(&copts, 0, sizeof(copts));
	copts.cb = end_sess_cb;

	rc = cldc_end_sess(udp->sess, &copts);
	if (rc) {
		fprintf(stderr, "cldc_end_sess failed: %d\n", rc);
		exit(1);
	}

	return 0;
}

static struct cldc_ops ops = {
	.timer_ctl		= cldc_levent_timer,
	.pkt_send		= cldc_udp_pkt_send,
	.event			= do_event,
};

static int init(void)
{
	int rc;
	struct cldc_call_opts copts;

	rc = cldc_udp_new("localhost", 18181, &udp);
	if (rc)
		return rc;

	memset(&copts, 0, sizeof(copts));
	copts.cb = new_sess_cb;

	rc = cldc_new_sess(&ops, &copts, udp->addr, udp->addr_len,
			   "testuser", "testuser", udp, &udp->sess);
	if (rc)
		return rc;

#if 0
	udp->sess->verbose = true;
#endif

	event_set(&udp_ev, udp->fd, EV_READ | EV_PERSIST, udp_event, udp);

	if (event_add(&udp_ev, NULL) < 0) {
		fprintf(stderr, "event_add failed\n");
		return 1;
	}

	return 0;
}

int main (int argc, char *argv[])
{
	event_init();
	if (init())
		return 1;
	event_dispatch();
	return final_rc;
}



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

#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libtimer.h>
#include <cldc.h>
#include "test.h"

static struct cldc_udp *udp;
static struct timer udp_tm;

static bool do_timer_ctl(void *priv, bool add,
			 int (*cb)(struct cldc_session *, void *),
			 void *cb_priv, time_t secs)
{
	if (priv != udp) {
		fprintf(stderr, "IE0: misuse of timer\n");
		exit(1);
	}

	if (add) {
		udp->cb = cb;
		udp->cb_private = cb_priv;
		timer_add(&udp_tm, time(NULL) + secs);
	} else {
		timer_del(&udp_tm);
	}

	return true;
}

static void timer_udp_event(struct timer *timer)
{
	if (timer->userdata != udp) {
		fprintf(stderr, "IE1: misuse of timer\n");
		exit(1);
	}

	if (udp->cb)
		udp->cb(udp->sess, udp->cb_private);
}

static void do_event(void *private, struct cldc_session *sess,
		     struct cldc_fh *fh, uint32_t event_mask)
{
	fprintf(stderr, "EVENT(%x)\n", event_mask);
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
	.timer_ctl		= do_timer_ctl,
	.pkt_send		= cldc_udp_pkt_send,
	.event			= do_event,
};

static int init(void)
{
	int rc;
	int port;
	struct cldc_call_opts copts;

	port = cld_readport("cld.port");	/* FIXME need test.h */
	if (port < 0)
		return port;
	if (port == 0)
		return -1;

	rc = cldc_udp_new("localhost", port, &udp);
	if (rc)
		return rc;

	timer_init(&udp_tm, "udp-timer", timer_udp_event, udp);

	memset(&copts, 0, sizeof(copts));
	copts.cb = new_sess_cb;

	rc = cldc_new_sess(&ops, &copts, udp->addr, udp->addr_len,
			   "testuser", "testuser", udp, &udp->sess);
	if (rc)
		return rc;

	// udp->sess->verbose = true;

	return 0;
}

int main (int argc, char *argv[])
{
	g_thread_init(NULL);
	cldc_init();
	if (init())
		return 1;
	test_loop(udp);
	return 0;
}


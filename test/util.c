
/*
 * General utilities for CLD tests.
 */

#define _GNU_SOURCE
#include "cld-config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libtimer.h>
#include <cldc.h>
#include "test.h"

void test_loop(struct cldc_udp *udp)
{
	int ufd = udp->fd;
	fd_set rset;
	struct timeval tm;
	time_t tmo;
	int rc;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(ufd, &rset);

		tmo = timers_run();
		if (tmo) {
			tm.tv_sec = tmo;
			tm.tv_usec = 0;
			rc = select(ufd + 1, &rset, NULL, NULL, &tm);
			if (rc < 0) {
				fprintf(stderr, "select: error\n");
				exit(1);
			}
			if (rc == 0)
				continue;
		} else {
			rc = select(ufd + 1, &rset, NULL, NULL, NULL);
			if (rc <= 0) {
				fprintf(stderr, "select: nfd %d\n", rc);
				exit(1);
			}
		}

		if (FD_ISSET(ufd, &rset)) {
			rc = cldc_udp_receive_pkt(udp);
			if (rc) {
				fprintf(stderr,
					"cldc_udp_receive_pkt: error %d\n", rc);
				exit(1);
			}
		} else {
			fprintf(stderr, "noevent\n");
			exit(1);
		}
	}
}


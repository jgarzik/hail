
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
#include <cldc.h>
#include "test.h"

void test_loop(struct cld_timer_list *tlist, struct cldc_udp *udp)
{
	int ufd = udp->fd;
	fd_set rset;
	struct timeval tm;
	time_t tmo;
	int rc;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(ufd, &rset);

		tmo = cld_timers_run(tlist);
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


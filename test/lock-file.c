
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
 * Create a file in CLD, lock it.
 */

#define _GNU_SOURCE
#include "hail-config.h"

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ncld.h>
#include "test.h"

static void sess_event(void *priv, unsigned int what)
{
	if (what == CE_SESS_FAILED) {
		fprintf(stderr, "Session failed\n");
		exit(1);
	}
	fprintf(stderr, "Unknown event %d\n", what);
}

int main (int argc, char *argv[])
{
	struct ncld_sess *nsess;
	struct ncld_fh *fh;
	int port;
	struct timespec tm;
	int error;
	int rc;

	g_thread_init(NULL);
	ncld_init();

	port = cld_readport(TEST_PORTFILE_CLD);
	if (port < 0)
		return port;
	if (port == 0)
		return -1;

	nsess = ncld_sess_open(TEST_HOST, port, &error, sess_event, NULL,
			     TEST_USER, TEST_USER_KEY, NULL);
	if (!nsess) {
		fprintf(stderr, "ncld_sess_open(host %s port %u) failed: %d\n",
			TEST_HOST, port, error);
		exit(1);
	}

	fh = ncld_open(nsess, TLNAME, COM_WRITE | COM_LOCK | COM_CREATE,
			&error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, "ncld_open(%s) failed: %d\n", TLNAME, error);
		exit(1);
	}

	rc = ncld_write(fh, LOCKSTR, LOCKLEN);
	if (rc) {
		fprintf(stderr, "ncld_write failed: %d\n", rc);
		exit(1);
	}

	rc = ncld_trylock(fh);
	if (rc) {
		fprintf(stderr, "ncld_trylock failed: %d\n", rc);
		exit(1);
	}

	printf("idling 40s...\n"); fflush(stdout);
	/* Idle for 40s to verify that session sustains a protocol ping. */
	tm.tv_sec = 40;
	tm.tv_nsec = 0;
	nanosleep(&tm, NULL);

	rc = ncld_unlock(fh);
	if (rc) {
		fprintf(stderr, "ncld_unlock failed: %d\n", rc);
		exit(1);
	}

	/* These two are perfect places to hang or crash, so don't just exit. */
	ncld_close(fh);
	ncld_sess_close(nsess);
	return 0;
}


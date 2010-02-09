
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
#include "cld-config.h"

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ncld.h>
#include "test.h"

int main (int argc, char *argv[])
{
	struct ncld_sess *nsp;
	struct ncld_fh *fhp;
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

	nsp = ncld_sess_open(TEST_HOST, port, &error, NULL, NULL,
			     TEST_USER, TEST_USER_KEY);
	if (!nsp) {
		fprintf(stderr, "ncld_sess_open(host %s port %u) failed: %d\n",
			TEST_HOST, port, error);
		exit(1);
	}

	fhp = ncld_open(nsp, TLNAME, COM_WRITE | COM_LOCK | COM_CREATE,
			&error, 0, NULL, NULL);
	if (!fhp) {
		fprintf(stderr, "ncld_open(%s) failed: %d\n", TLNAME, error);
		exit(1);
	}

	rc = ncld_write(fhp, LOCKSTR, LOCKLEN);
	if (rc) {
		fprintf(stderr, "ncld_write failed: %d\n", rc);
		exit(1);
	}

	rc = ncld_trylock(fhp);
	if (rc) {
		fprintf(stderr, "ncld_trylock failed: %d\n", rc);
		exit(1);
	}

	printf("idling 40s...\n"); fflush(stdout);
	/* Idle for 40s to verify that session sustains a protocol ping. */
	tm.tv_sec = 40;
	tm.tv_nsec = 0;
	nanosleep(&tm, NULL);

	rc = ncld_unlock(fhp);
	if (rc) {
		fprintf(stderr, "ncld_unlock failed: %d\n", rc);
		exit(1);
	}

	/* These two are perfect places to hang or crash, so don't just exit. */
	ncld_close(fhp);
	ncld_sess_close(nsp);
	return 0;
}


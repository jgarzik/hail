
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
 * Create a file in CLD.
 */

#define _GNU_SOURCE
#include "cld-config.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ncld.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct ncld_sess *nsp;
	struct ncld_fh *fhp;
	int port;
	int error;

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

	fhp = ncld_open(nsp, TFNAME, COM_WRITE | COM_CREATE,
			&error, 0, NULL, NULL);
	if (!fhp) {
		fprintf(stderr, "ncld_open(%s) failed: %d\n", TFNAME, error);
		exit(1);
	}

	error = ncld_write(fhp, TESTSTR, TESTLEN);
	if (error) {
		fprintf(stderr, "ncld_write failed: %d\n", error);
		exit(1);
	}

	/* These two are perfect places to hang or crash, so don't just exit. */
	ncld_close(fhp);
	ncld_sess_close(nsp);
	return 0;
}


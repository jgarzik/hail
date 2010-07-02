
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
 * Create and read back file in CLD.
 */

#define _GNU_SOURCE
#include "hail-config.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ncld.h>
#include "test.h"

static int test_write(int port)
{
	struct ncld_sess *nsess;
	struct ncld_fh *fh;
	int error;

	nsess = ncld_sess_open(TEST_HOST, port, &error, NULL, NULL,
			     TEST_USER, TEST_USER_KEY, NULL);
	if (!nsess) {
		fprintf(stderr, "ncld_sess_open(host %s port %u) failed: %d\n",
			TEST_HOST, port, error);
		exit(1);
	}

	fh = ncld_open(nsess, TFNAME, COM_WRITE | COM_CREATE,
			&error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, "ncld_open(%s) failed: %d\n", TFNAME, error);
		exit(1);
	}

	error = ncld_write(fh, TESTSTR, TESTLEN);
	if (error) {
		fprintf(stderr, "ncld_write failed: %d\n", error);
		exit(1);
	}

	/* These two are perfect places to hang or crash, so don't just exit. */
	ncld_close(fh);
	ncld_sess_close(nsess);
	return 0;
}

static int test_read(int port)
{
	struct ncld_sess *nsess;
	struct ncld_fh *fh;
	struct ncld_read *rp;
	int error;

	nsess = ncld_sess_open(TEST_HOST, port, &error, NULL, NULL,
			     TEST_USER, TEST_USER_KEY, NULL);
	if (!nsess) {
		fprintf(stderr, "ncld_sess_open(host %s port %u) failed: %d\n",
			TEST_HOST, port, error);
		exit(1);
	}

	fh = ncld_open(nsess, TFNAME, COM_READ, &error, 0, NULL, NULL);
	if (!fh) {
		fprintf(stderr, "ncld_open(%s) failed: %d\n", TFNAME, error);
		exit(1);
	}

	rp = ncld_get(fh, &error);
	if (!rp) {
		fprintf(stderr, "ncld_get failed: %d\n", error);
		exit(1);
	}

	if (rp->length != TESTLEN) {
		fprintf(stderr, "Bad CLD file length %ld\n", rp->length);
		exit(1);
	}

	if (memcmp(rp->ptr, TESTSTR, TESTLEN)) {
		fprintf(stderr, "Bad CLD file content\n");
		exit(1);
	}

	ncld_read_free(rp);

	/* These two are perfect places to hang or crash, so don't just exit. */
	ncld_close(fh);
	ncld_sess_close(nsess);
	return 0;
}

int main(int argc, char *argv[])
{
	int port;

	g_thread_init(NULL);
	ncld_init();

	port = cld_readport(TEST_PORTFILE_CLD);
	if (port < 0)
		return 1;
	if (port == 0)
		return 1;

	if (test_write(port))
		return 1;
	if (test_read(port))
		return 1;

	return 0;
}


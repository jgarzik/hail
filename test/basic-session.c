
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
#include "hail-config.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ncld.h>
#include "test.h"

int main (int argc, char *argv[])
{
	struct ncld_sess *nsess;
	int error;
	int port;

	g_thread_init(NULL);
	ncld_init();

	port = cld_readport(TEST_PORTFILE_CLD);
	if (port < 0)
		return port;
	if (port == 0)
		return -1;

	nsess = ncld_sess_open(TEST_HOST, port, &error, NULL, NULL,
			     TEST_USER, TEST_USER_KEY, NULL);
	if (!nsess) {
		fprintf(stderr, "ncld_sess_open(host %s port %u) failed: %d\n",
			TEST_HOST, port, error);
		exit(1);
	}

	ncld_sess_close(nsess);
	return 0;
}


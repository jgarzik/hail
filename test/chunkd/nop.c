
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
#include "chunkd-config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <chunkc.h>
#include "test.h"

enum {
	N_NOPS			= 50000,
};

static void test(int n_nops, bool do_encrypt)
{
	struct st_client *stc;
	int port;
	bool rcb;
	int i;
	struct timeval ta, tb;

	port = stc_readport(TEST_PORTFILE);
	OK(port > 0);

	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, do_encrypt);
	OK(stc);

	rcb = stc_table_openz(stc, TEST_TABLE, 0);
	OK(rcb);

	gettimeofday(&ta, NULL);

	/* send NOP messages */
	for (i = 0; i < n_nops; i++) {
		rcb = stc_ping(stc);
		OK(rcb);
	}

	gettimeofday(&tb, NULL);

	printdiff(&ta, &tb, n_nops,
		  do_encrypt ? "nop SSL NOP": "nop NOP", "nops");

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	int n_nops = N_NOPS;

	setlocale(LC_ALL, "C");

	stc_init();
	SSL_library_init();
	SSL_load_error_strings();

	if (argc == 2 && (atoi(argv[1]) > 0)) {
		n_nops = atoi(argv[1]);
		fprintf(stderr, "testing %d nops...\n", n_nops);
	}

	test(n_nops, false);
	test(n_nops, true);

	return 0;
}


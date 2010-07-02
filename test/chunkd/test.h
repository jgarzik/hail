#ifndef __TABLED_TEST_H__
#define __TABLED_TEST_H__

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

#include <stdint.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_HOST "localhost"

#define TEST_TABLE "test"

#define TEST_USER "testuser"
#define TEST_USER_KEY "testuser"

#define TEST_USER2 "testuser2"
#define TEST_USER2_KEY "testuser2"

#define TEST_PORTFILE_CLD	"cld.port"
#define TEST_PORTFILE		"chunkd.port"

#define TEST_CHUNKD_CFG		"server-test.cfg"

#define OK(expr)				\
	do {					\
		if (!(expr)) {			\
			fprintf(stderr, "test failed on line %d\n", \
				__LINE__);	\
			exit(1);		\
		}				\
	} while (0)

extern void printdiff(const struct timeval *t_start, const struct timeval *t_end,
	       int64_t val_i, const char *pfx, const char *units);

#endif /* __TABLED_TEST_H__ */

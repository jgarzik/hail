
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
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "test.h"

#define RNGFN "/dev/urandom"

static long double tv2ld(const struct timeval *tv)
{
	long double ds = tv->tv_sec;
	long double du = tv->tv_usec * 0.000001;
	long double res = ds + du;

	if (res == 0.0)
		return 0.001;

	return res;
}

void printdiff(const struct timeval *t_start, const struct timeval *t_end,
	       int64_t val_i, const char *pfx, const char *units)
{
	long double d_start = tv2ld(t_start);
	long double d_end = tv2ld(t_end);
	long double elapsed = d_end - d_start;

	long double val = val_i;
	long double quo = val / elapsed;

	fprintf(stderr, "      %s: %.2Lf %s/sec\n", pfx, quo, units);
}

void *randmem(size_t n)
{
	void *mem;
	int fd;
	ssize_t rrc;

	mem = malloc(n);
	if (!mem)
		return NULL;
	
	fd = open(RNGFN, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, RNGFN ": %s\n", strerror(errno));
		goto err_out;
	}

	rrc = read(fd, mem, n);
	if (rrc < 0) {
		fprintf(stderr, "read " RNGFN ": %s\n", strerror(errno));
		goto err_out;
	}
	if (rrc != n) {
		fprintf(stderr, "short read " RNGFN ": %ld < %lu\n",
			(long) rrc,
			(unsigned long) n);
		goto err_out;
	}

	if (close(fd) < 0) {
		fprintf(stderr, "close " RNGFN ": %s\n", strerror(errno));
		goto err_out;
	}

	return mem;

err_out:
	free(mem);
	return NULL;
}


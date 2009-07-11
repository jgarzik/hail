
#include "chunkd-config.h"
#include <stdio.h>
#include "test.h"

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


#ifndef __TABLED_TEST_H__
#define __TABLED_TEST_H__

#include <stdint.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_HOST "localhost"

#define TEST_USER "testuser"
#define TEST_USER_KEY "testuser"

#define TEST_USER2 "testuser2"
#define TEST_USER2_KEY "testuser2"

#define TEST_PORTFILE_CLD	"cld.port"
#define TEST_PORTFILE		"chunkd.port"
#define TEST_PORTFILE_SSL	"chunkd-ssl.port"

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

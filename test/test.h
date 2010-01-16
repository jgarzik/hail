#ifndef _CLD_TEST_H_
#define _CLD_TEST_H_

#include <stdbool.h>
#include <cldc.h>
#include <libtimer.h>

#define TESTSTR          "longertestdata\n"
#define TESTLEN  (sizeof("longertestdata\n")-1)

#define LOCKSTR          "testlock\n"
#define LOCKLEN  (sizeof("testlock\n")-1)

#define TFNAME     "/cld-test-inst"
#define TLNAME     "/cld-lock-inst"

#define TEST_HOST "localhost"

#define TEST_USER "testuser"
#define TEST_USER_KEY "testuser"

#define TEST_PORTFILE_CLD	"cld.port"

extern void test_loop(struct cld_timer_list *tlist, struct cldc_udp *udp);

#endif

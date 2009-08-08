
#include "chunkd-config.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <chunkc.h>
#include "test.h"

static void test(bool ssl)
{
	struct st_client *stc;
	bool rcb;

	stc = stc_new(TEST_HOST, ssl ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, ssl);
	OK(stc);

	rcb = stc_ping(stc);
	OK(rcb);

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	stc_init();
	SSL_library_init();
	SSL_load_error_strings();

	test(false);
	test(true);

	return 0;
}

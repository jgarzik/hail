
#include "chunkd-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

static void test(bool ssl)
{
	struct st_client *stc;

	stc = stc_new(TEST_HOST, ssl ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, ssl);
	OK(stc);

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	test(false);
	test(true);

	return 0;
}


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

static void test(int n_nops, bool encrypt)
{
	struct st_client *stc;
	int port;
	bool rcb;
	int i;
	struct timeval ta, tb;

	port = stc_readport(encrypt ? TEST_PORTFILE_SSL : TEST_PORTFILE);
	OK(port > 0);

	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	gettimeofday(&ta, NULL);

	/* send NOP messages */
	for (i = 0; i < n_nops; i++) {
		rcb = stc_ping(stc);
		OK(rcb);
	}

	gettimeofday(&tb, NULL);

	printdiff(&ta, &tb, n_nops,
		  encrypt ? "nop SSL NOP": "nop NOP", "nops");

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



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
	N_BUFS		= 100,
	BUFSZ		= 1024 * 1024,
};

static bool send_buf(struct st_client *stc, int sfd, void *buf, size_t buf_len)
{
	int sent;
	fd_set rset, wset;
	int rc;

	/*
	 * This is a trick. We poll the receive side in case SSL needs it.
	 */
	sent = 0;
	while (buf_len) {
		FD_ZERO(&wset);
		FD_SET(sfd, &wset);
		FD_SET(sfd, &rset);
		rc = select(sfd + 1, &rset, &wset, NULL, NULL);
		OK(rc >= 0);
		OK(FD_ISSET(sfd, &rset) || FD_ISSET(sfd, &wset));

		rc = stc_put_send(stc, buf + sent, buf_len);
		OK(rc >= 0);
		sent += rc;
		buf_len -= rc;
	}
	return true;
}

static bool recv_buf(struct st_client *stc, int rfd, void *buf, size_t buf_len)
{
	int rcvd;
	fd_set rset;
	int rc;

	/*
	 * This is a trick. We must check if SSL library had something
	 * prebuffered first, or else select may hang forever.
	 */
	rcvd = 0;
	for (;;) {
		rc = stc_get_recv(stc, buf + rcvd, buf_len);
		OK(rc >= 0);
		rcvd += rc;
		buf_len -= rc;

		if (buf_len == 0)
			break;

		FD_ZERO(&rset);
		FD_SET(rfd, &rset);
		rc = select(rfd + 1, &rset, NULL, NULL, NULL);
		OK(rc >= 0);
		OK(FD_ISSET(rfd, &rset));
	}
	return true;
}

static void test(bool encrypt)
{
	struct st_object *obj;
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char key[64] = "deadbeef";
	size_t len = 0;
	char data[BUFSZ];
	char rbuf[BUFSZ];
	struct timeval ta, tb;
	int sfd, rfd;
	int i;

	memset(data, 0xdeadbeef, sizeof(data));

	stc = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	sync();

	gettimeofday(&ta, NULL);

	/* store object */
	rcb = stc_put_start(stc, key, N_BUFS * BUFSZ, &sfd);
	OK(rcb);
	for (i = 0; i < N_BUFS; i++) {
		rcb = send_buf(stc, sfd, data, BUFSZ);
		OK(rcb);
	}
	rcb = stc_put_sync(stc);
	OK(rcb);

	gettimeofday(&tb, NULL);

	printdiff(&ta, &tb, N_BUFS,
		  encrypt ? "large-object SSL PUT" : "large-object PUT", "MB");

	sync();

	/* make sure object appears in list of volume keys */
	klist = stc_keys(stc);
	OK(klist);
	OK(klist->contents);
	OK(klist->contents->next == NULL);

	obj = klist->contents->data;
	OK(obj);
	OK(obj->name);
	OK(!strcmp(obj->name, key));
	OK(obj->time_mod);
	OK(obj->etag);
	OK(obj->size == (N_BUFS * BUFSZ));
	OK(obj->owner);

	gettimeofday(&ta, NULL);

	/* initiate get object */
	rcb = stc_get_start(stc, key, &rfd, &len);
	OK(rcb);
	OK(len == (N_BUFS * BUFSZ));

	gettimeofday(&tb, NULL);

	printdiff(&ta, &tb, N_BUFS,
		  encrypt ? "large-object SSL GET" : "large-object GET", "MB");

	/* get and verify object contents */
	for (i = 0; i < N_BUFS; i++) {
		rcb = recv_buf(stc, rfd, rbuf, BUFSZ);
		OK(rcb);
		OK(!memcmp(rbuf, data, BUFSZ));
	}

	/* delete object */
	rcb = stc_del(stc, key);
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

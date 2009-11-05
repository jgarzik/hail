
#include "chunkd-config.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <chunkc.h>
#include "test.h"

static void test(bool encrypt)
{
	struct st_object *obj;
	struct st_keylist *klist;
	struct st_client *stc;
	int port;
	bool rcb;
	char val[] = "my first value";
	char key[64] = "deadbeef";
	size_t len = 0;
	void *mem;

	port = stc_readport(encrypt ? TEST_PORTFILE_SSL : TEST_PORTFILE);
	OK(port > 0);

	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	/* store object */
	rcb = stc_put_inlinez(stc, key, val, strlen(val));
	OK(rcb);

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
	OK(obj->size == strlen(val));
	OK(obj->owner);

	stc_free_keylist(klist);

	/* get object */
	mem = stc_get_inlinez(stc, key, &len);
	OK(mem);
	OK(len == strlen(val));
	OK(!memcmp(val, mem, strlen(val)));

	free(mem);

	/* delete object */
	rcb = stc_delz(stc, key);
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

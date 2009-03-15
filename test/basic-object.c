
#include "chunkd-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

static void test(bool encrypt)
{
	struct st_object *obj;
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char val[] = "my first value";
	char key[64] = "deadbeef";
	size_t len = 0;
	void *mem;

	stc = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	/* store object */
	rcb = stc_put_inline(stc, key, val, strlen(val));
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
	mem = stc_get_inline(stc, key, false, &len);
	OK(mem);
	OK(len == strlen(val));
	OK(!memcmp(val, mem, strlen(val)));

	free(mem);

	/* delete object */
	rcb = stc_del(stc, key);
	OK(rcb);

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	SSL_library_init();
	SSL_load_error_strings();

	test(false);
	test(true);

	return 0;
}

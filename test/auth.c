
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
	struct st_client *stc1, *stc2;
	bool rcb;
	char val1[] = "my first value";
	char val2[] = "my second value";
	char key1[64] = "deadbeef";
	char key2[64] = "bedac0ed";
	size_t len = 0;
	void *mem;

	stc1 = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc1);

	stc2 = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER2, TEST_USER2_KEY, encrypt);
	OK(stc2);

	/* store object 1 */
	rcb = stc_put_inline(stc1, key1, val1, strlen(val1));
	OK(rcb);

	/* store object 2 */
	rcb = stc_put_inline(stc2, key2, val2, strlen(val2));
	OK(rcb);

	/* make sure object 1 appears in list of volume keys */
	klist = stc_keys(stc1);
	OK(klist);
	OK(klist->contents);
	OK(klist->contents->next == NULL);

	obj = klist->contents->data;
	OK(obj);
	OK(obj->name);
	OK(!strcmp(obj->name, key1));
	OK(obj->time_mod);
	OK(obj->etag);
	OK(obj->size == strlen(val1));
	OK(obj->owner);

	stc_free_keylist(klist);

	/* make sure object 2 appears in list of volume keys */
	klist = stc_keys(stc2);
	OK(klist);
	OK(klist->contents);
	OK(klist->contents->next == NULL);

	obj = klist->contents->data;
	OK(obj);
	OK(obj->name);
	OK(!strcmp(obj->name, key2));
	OK(obj->time_mod);
	OK(obj->etag);
	OK(obj->size == strlen(val2));
	OK(obj->owner);

	stc_free_keylist(klist);

	/* get object 1 */
	mem = stc_get_inline(stc1, key1, &len);
	OK(mem);
	OK(len == strlen(val1));
	OK(!memcmp(val1, mem, strlen(val1)));

	free(mem);

	/* fail to get object 2 */
	mem = stc_get_inline(stc1, key2, &len);
	OK(mem == NULL);

	/* get object 2 */
	mem = stc_get_inline(stc2, key2, &len);
	OK(mem);
	OK(len == strlen(val2));
	OK(!memcmp(val2, mem, strlen(val2)));

	free(mem);

	/* fail to get object 1 */
	mem = stc_get_inline(stc2, key1, &len);
	OK(mem == NULL);

	/* fail to delete object 2 */
	rcb = stc_del(stc1, key2);
	OK(rcb == false);

	/* fail to delete object 1 */
	rcb = stc_del(stc2, key1);
	OK(rcb == false);

	/* delete object 1 */
	rcb = stc_del(stc1, key1);
	OK(rcb);

	/* delete object 2 */
	rcb = stc_del(stc2, key2);
	OK(rcb);

	stc_free(stc1);
	stc_free(stc2);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	srand(time(NULL) ^ getpid());

	SSL_library_init();
	SSL_load_error_strings();

	test(false);
	test(true);

	return 0;
}

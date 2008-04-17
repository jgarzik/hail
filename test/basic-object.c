
#include "storaged-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct st_object *obj;
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char val[] = "my first value";
	char key[64] = "";
	size_t len = 0;
	void *mem;

	setlocale(LC_ALL, "C");

	stc = stc_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(stc);

	/* store object */
	rcb = stc_put_inline(stc, "testvol", val, strlen(val), key);
	OK(rcb);

	/* make sure object appears in list of volume keys */
	klist = stc_keys(stc, "testvol");
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

	/* get object */
	mem = stc_get_inline(stc, "testvol", key, false, &len);
	OK(mem);
	OK(len == strlen(val));
	OK(!memcmp(val, mem, strlen(val)));

	/* delete object */
	rcb = stc_del(stc, "testvol", key);
	OK(rcb);

	return 0;
}

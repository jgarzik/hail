
#include "chunkd-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

enum {
	N_TEST_OBJS		= 1000,
};

static void test(int n_objects, bool encrypt)
{
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char val[] = "my first value";
	char key[64] = "";
	int i;
	GList *keys = NULL, *tmpl;
	char *k;

	stc = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	/* store object */
	for (i = 0; i < n_objects; i++) {
		sprintf(key, "%08x", i);
		rcb = stc_put_inline(stc, key, val, strlen(val));
		OK(rcb);

		keys = g_list_prepend(keys, strdup(key));
	}

	/* verify keylist is received */
	klist = stc_keys(stc);
	OK(klist);
	OK(klist->contents);

	i = 0;
	tmpl = klist->contents;
	while (tmpl) {
		i++;
		tmpl = tmpl->next;
	}

	OK(i == n_objects);

	stc_free_keylist(klist);

	/* get objects */
	for (tmpl = keys; tmpl; tmpl = tmpl->next) {
		size_t len;
		void *mem;

		k = tmpl->data;
		len = 0;

		mem = stc_get_inline(stc, k, false, &len);
		OK(mem);
		OK(len == strlen(val));
		OK(!memcmp(val, mem, strlen(val)));

		free(mem);
	}

	/* delete object */
	for (tmpl = keys; tmpl; tmpl = tmpl->next) {
		k = tmpl->data;
		rcb = stc_del(stc, k);
		OK(rcb);

		free(k);
	}

	g_list_free(keys);

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	int n_objects = N_TEST_OBJS;

	setlocale(LC_ALL, "C");

	if (argc == 2 && (atoi(argv[1]) > 0)) {
		n_objects = atoi(argv[1]);
		fprintf(stderr, "testing %d objects...\n", n_objects);
	}

	test(n_objects, false);
	test(n_objects, true);

	return 0;
}


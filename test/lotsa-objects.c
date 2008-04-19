
#include "storaged-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

enum {
	N_TEST_OBJS		= 1000,
};

int main(int argc, char *argv[])
{
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char val[] = "my first value";
	char key[64] = "";
	int i;
	GList *keys = NULL, *tmpl;
	char *k;
	int n_objects = N_TEST_OBJS;

	setlocale(LC_ALL, "C");

	if (argc == 2 && (atoi(argv[1]) > 0)) {
		n_objects = atoi(argv[1]);
		fprintf(stderr, "testing %d objects...\n", n_objects);
	}

	stc = stc_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(stc);

	/* store object */
	for (i = 0; i < n_objects; i++) {
		rcb = stc_put_inline(stc, "testvol", val, strlen(val), key);
		OK(rcb);

		keys = g_list_prepend(keys, strdup(key));
	}

	/* verify keylist is received */
	klist = stc_keys(stc, "testvol");
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

		mem = stc_get_inline(stc, "testvol", k, false, &len);
		OK(mem);
		OK(len == strlen(val));
		OK(!memcmp(val, mem, strlen(val)));

		free(mem);
	}

	/* delete object */
	for (tmpl = keys; tmpl; tmpl = tmpl->next) {
		k = tmpl->data;
		rcb = stc_del(stc, "testvol", k);
		OK(rcb);
	}

	stc_free(stc);

	return 0;
}

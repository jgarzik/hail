
#include "chunkd-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

static void test(bool ssl)
{
	struct st_client *stc;
	struct st_vlist *vlist;
	struct st_volume *vol;

	stc = stc_new(TEST_HOST, ssl ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, ssl);
	OK(stc);

	vlist = stc_list_volumes(stc);
	OK(vlist);
	OK(vlist->list);
	OK(vlist->list->next == NULL);

	vol = vlist->list->data;
	OK(vol);
	OK(vol->name);
	OK(!strcmp(vol->name, "testvol"));

	OK(!strcmp(vlist->owner, stc->user));

	stc_free_vlist(vlist);
	stc_free(stc);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	test(false);
	test(true);

	return 0;
}

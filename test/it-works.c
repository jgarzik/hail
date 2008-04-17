
#include "storaged-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct st_client *stc;
	struct st_vlist *vlist;
	struct st_volume *vol;

	setlocale(LC_ALL, "C");

	stc = stc_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
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

	stc_free(stc);

	return 0;
}

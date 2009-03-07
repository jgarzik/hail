
#include "storaged-config.h"
#include <string.h>
#include <locale.h>
#include <stc.h>
#include "test.h"

enum {
	N_BUFS		= 4000,
	BUFSZ		= 4096,
};

static unsigned long read_offset;

static size_t read_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	size_t len = size * nmemb;
	unsigned long slop_ofs, slop_len;

	if (read_offset >= (N_BUFS * BUFSZ))
		return 0;

	slop_ofs = read_offset & (BUFSZ - 1);
	slop_len = BUFSZ - slop_ofs;
	len = MIN(len, slop_len);
	memcpy(ptr, user_data + slop_ofs, len);

	read_offset += len;

	return len;
}

static void test(bool encrypt)
{
	struct st_object *obj;
	struct st_keylist *klist;
	struct st_client *stc;
	bool rcb;
	char key[64] = "deadbeef";
	size_t len = 0;
	void *mem, *p;
	char data[BUFSZ];
	int i;

	memset(data, 0xdeadbeef, sizeof(data));

	stc = stc_new(TEST_HOST, encrypt ? TEST_SSL_PORT : TEST_PORT,
		      TEST_USER, TEST_USER_KEY, encrypt);
	OK(stc);

	/* store object */
	rcb = stc_put(stc, "testvol", key, read_cb, N_BUFS * BUFSZ, data);
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
	OK(obj->size == (N_BUFS * BUFSZ));
	OK(obj->owner);

	/* get object */
	mem = stc_get_inline(stc, "testvol", key, false, &len);
	OK(mem);
	OK(len == (N_BUFS * BUFSZ));

	/* verify object contents */
	p = mem;
	for (i = 0; i < N_BUFS; i++) {
		OK(!memcmp(p, data, BUFSZ));
		p += BUFSZ;
	}

	/* delete object */
	rcb = stc_del(stc, "testvol", key);
	OK(rcb);

	stc_free(stc);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	test(false);

	read_offset = 0;
	test(true);

	return 0;
}

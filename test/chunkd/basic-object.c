
/*
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define _GNU_SOURCE
#include "hail-config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <cld_common.h>
#include <chunkc.h>
#include "test.h"

static void test(bool do_encrypt)
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

	port = hail_readport(TEST_PORTFILE);
	OK(port > 0);

	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, do_encrypt);
	OK(stc);

	rcb = stc_table_openz(stc, TEST_TABLE, 0);
	OK(rcb);

	/* store object */
	rcb = stc_put_inlinez(stc, key, val, strlen(val), 0);
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


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

#include "../server/objcache.c"
#include "test.h"

int main(int argc, char *argv[])
{
	static char k1[] = { 'a' };
	static char k2[] = { 'a', 'a' };
	static char k3[] = { 'a', '\0', 'a' };
	struct objcache cache;
	struct objcache_entry *ep1, *ep2, *ep3;
	int rc;

	g_thread_init(NULL);
	rc = objcache_init(&cache);
	OK(rc==0);

	ep1 = objcache_get(&cache, k1, sizeof(k1));
	OK(ep1 != NULL);

	ep2 = objcache_get(&cache, k2, sizeof(k2));
	OK(ep2 != NULL);

	ep3 = objcache_get(&cache, k3, sizeof(k3));
	OK(ep3 != NULL);

	rc = objcache_count(&cache);
	OK(rc == 3);

	OK(ep1->ref == 1);	/* no collisions, else improve hash */

	objcache_put(&cache, ep1);
	objcache_put(&cache, ep2);
	objcache_put(&cache, ep3);

	ep2 = objcache_get(&cache, k2, sizeof(k2));
	OK(ep2 != NULL);
	OK(ep2->ref == 1);	/* new */
	objcache_put(&cache, ep2);

	rc = objcache_count(&cache);
	OK(rc == 0);

	objcache_fini(&cache);
	return 0;
}

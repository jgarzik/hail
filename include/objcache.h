
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
#ifndef _CHUNKD_OBJCACHE_H_
#define _CHUNKD_OBJCACHE_H_

#include <glib.h>
#include <stdbool.h>

struct objcache {
	GMutex *lock;
	GHashTable *table;
};

struct objcache_entry {
	unsigned int hash;
	unsigned int flags;
	int ref;
};

#define OC_F_DIRTY   0x1

/*
 * Get an entry and set flags.
 * A method for every flag is needed because our locks are internal to
 * the cache, and we want this to be atomic.
 */
#define objcache_get(c, k, l)		__objcache_get(c, k, l, 0)
#define objcache_get_dirty(c, k, l)	__objcache_get(c, k, l, OC_F_DIRTY)
extern struct objcache_entry *__objcache_get(struct objcache *cache,
					     const char *key, int klen,
					     unsigned int flag);

/*
 * Test for dirty.
 */
extern bool objcache_test_dirty(struct objcache *cache,
				struct objcache_entry *entry);

/*
 * Put an entry (decrement and free, or an equivalent).
 */
extern void objcache_put(struct objcache *cache, struct objcache_entry *entry);

/*
 * Count objects in the cache. Can be slow, and used only for debugging.
 */
extern int objcache_count(struct objcache *cache);

/*
 * Init a cache. Call once. May fail since it allocates a mutex.
 */
extern int objcache_init(struct objcache *cache);

/*
 * Terminate a cache.
 */
extern void objcache_fini(struct objcache *cache);

#endif

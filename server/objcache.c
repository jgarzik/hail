
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

#include <objcache.h>
#include <stdlib.h>

/*
 * We really should not screw around with hand-rolled garbage and use
 * something like Paul Hsieh's SuperFastHash, but licenses are too confusing.
 */
static unsigned int objcache_hash(const char *key, int klen)
{
	unsigned int hash;
	int i;
	unsigned char c;

	hash = 0x55555555;
	for (i = 0; i < klen; i++) {
		c = (unsigned char) *key++;
		hash ^= hash << 16;
		hash ^= c;
		hash = (hash << 8) | (hash >> 24);
	}
	return hash;
}

static struct objcache_entry *objcache_insert(struct objcache *cache,
					      unsigned int hash)
{
	struct objcache_entry *cep;

	cep = malloc(sizeof(struct objcache_entry));
	if (!cep)
		return NULL;
	cep->hash = hash;
	cep->flags = 0;
	cep->ref = 1;
	g_hash_table_insert(cache->table, &cep->hash, cep);
	return cep;
}

/*
 * Observe the way we handle conflicts in the computed hash: we treat the
 * keys with the same hash as same. It's acceptable in our application.
 * At worst, an unrelated activity main in chunkd may spook self-check.
 * This policy remains the same for list, tree, hash or any other implementing
 * structure. If we use Glib's hash, it can have its own conflicts over
 * a shared bucket indexed with our hash. We don't know anything about those.
 */
struct objcache_entry *__objcache_get(struct objcache *cache,
				      const char *key, int klen,
				      unsigned int flag)
{
	struct objcache_entry *cep;
	unsigned int hash;

	hash = objcache_hash(key, klen);
	g_mutex_lock(cache->lock);
	cep = g_hash_table_lookup(cache->table, &hash);
	if (cep) {
		cep->ref++;
	} else {
		cep = objcache_insert(cache, hash);
	}
	cep->flags |= flag;
	g_mutex_unlock(cache->lock);
	return cep;
}

bool objcache_test_dirty(struct objcache *cache, struct objcache_entry *cep)
{
	bool ret;

	g_mutex_lock(cache->lock);
	ret = cep->flags & OC_F_DIRTY;
	g_mutex_unlock(cache->lock);
	return ret;
}

void objcache_put(struct objcache *cache, struct objcache_entry *cep)
{
	g_mutex_lock(cache->lock);
	if (!cep->ref) {
		g_mutex_unlock(cache->lock);
		/* Must not happen, or a leak for Valgrind to catch. */
		return;
	}
	--cep->ref;
	if (!cep->ref) {
		gboolean rcb;
		rcb = g_hash_table_remove(cache->table, &cep->hash);
		/*
		 * We are so super sure that this cannot happen that
		 * we use abort(), which is not welcome in daemons.
		 */
		if (!rcb)
			abort();
		free(cep);
	}
	g_mutex_unlock(cache->lock);
}

int objcache_count(struct objcache *cache)
{
	return g_hash_table_size(cache->table);
}

int objcache_init(struct objcache *cache)
{
	cache->lock = g_mutex_new();
	if (!cache->lock)
		return -1;
	/* We do not use g_str_hash becuse our keys may have nul bytes. */
	cache->table = g_hash_table_new(g_int_hash, g_int_equal);
	return 0;
}

void objcache_fini(struct objcache *cache)
{
	g_mutex_free(cache->lock);
	g_hash_table_destroy(cache->table);
}

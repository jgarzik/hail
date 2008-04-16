
#include "storaged-config.h"
#include <errno.h>
#include "storaged.h"

int register_storage(struct backend_info *be)
{
	if (!storaged_srv.backends) {
		storaged_srv.backends = g_hash_table_new_full(
			g_str_hash, g_str_equal, NULL, NULL);
		if (!storaged_srv.backends)
			return -ENOMEM;
	}

	g_hash_table_insert(storaged_srv.backends,
			    (gpointer) be->name, be);

	return 0;
}

void unregister_storage(struct backend_info *be)
{
	g_hash_table_remove(storaged_srv.backends, be->name);

	if (g_hash_table_size(storaged_srv.backends) == 0) {
		g_hash_table_destroy(storaged_srv.backends);
		storaged_srv.backends = NULL;
	}
}


#include "storaged-config.h"
#include "storaged.h"

#define BE_NAME		"fs"

static struct backend_info be_fs_info = {
	.name		= BE_NAME,
};

int be_fs_init(void)
{
	return register_storage(&be_fs_info);
}

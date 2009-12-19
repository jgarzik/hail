
#define _GNU_SOURCE
#include "cld-config.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <cld-private.h>
#include "cld_msg.h"

/* duplicated from tools/cldcli.c; put in common header somewhere? */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

unsigned long long cld_sid2llu(const uint8_t *sid)
{
	const uint64_t *v_le = (const uint64_t *) sid;
	uint64_t v = le64_to_cpu(*v_le);
	return v;
}

void __cld_rand64(void *p)
{
	uint32_t *v = p;

	v[0] = rand();
	v[1] = rand();
}

static const char *cld_errlist[] =
{
	[CLE_OK]		= "Success",
	[CLE_SESS_EXISTS]	= "Session exists",
	[CLE_SESS_INVAL]	= "Invalid session",
	[CLE_DB_ERR]		= "Database error",
	[CLE_BAD_PKT]		= "Invalid/corrupted packet",
	[CLE_INODE_INVAL]	= "Invalid inode number",
	[CLE_NAME_INVAL]	= "Invalid file name",
	[CLE_OOM]		= "Server out of memory",
	[CLE_FH_INVAL]		= "Invalid file handle",
	[CLE_DATA_INVAL]	= "Invalid data packet",
	[CLE_LOCK_INVAL]	= "Invalid lock",
	[CLE_LOCK_CONFLICT]	= "Conflicting lock held",
	[CLE_LOCK_PENDING]	= "Lock waiting to be acquired",
	[CLE_MODE_INVAL]	= "Operation incompatible with file mode",
	[CLE_INODE_EXISTS]	= "File exists",
	[CLE_DIR_NOTEMPTY]	= "Directory not empty",
	[CLE_INTERNAL_ERR]	= "Internal error",
	[CLE_TIMEOUT]		= "Session timed out",
	[CLE_SIG_INVAL]		= "Bad HMAC signature",
};

const char *cld_errstr(enum cle_err_codes ecode)
{
	if (ecode >= ARRAY_SIZE(cld_errlist))
		return "(unknown)";

	return cld_errlist[ecode];
}

/*
 * Read a port number from a port file, return the value or negative error.
 */
int cld_readport(const char *fname)
{
	long port;
	gchar *buf;
	GError *err = NULL;
	gsize len;

	if (!g_file_get_contents(fname, &buf, &len, &err)) {
		int ret = -1000 - err->code;
		g_error_free(err);
		return ret;
	}

	if (len == 0) {
		g_free(buf);
		return -EPIPE;
	}
	port = strtol(buf, NULL, 10);
	g_free(buf);
	if (port <= 0 || port >= 65636)
		return -EDOM;

	return (int)port;
}


#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "storaged.h"

#define BE_NAME		"fs"

struct fs_obj {
	struct backend_obj	bo;

	int			out_fd;
	char			*out_fn;

	int			in_fd;
	char			*in_fn;

	struct database		*db;
};

static uint64_t global_counter;

static uint64_t next_counter(void)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	uint64_t rv;

	g_static_mutex_lock (&mutex);

	rv = global_counter++;

	g_static_mutex_unlock (&mutex);

	return rv;
}

static struct fs_obj *fs_obj_alloc(struct server_volume *vol,
				   struct database *db)
{
	struct fs_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	obj->bo.private = obj;
	obj->bo.vol = vol;

	obj->out_fd = -1;
	obj->in_fd = -1;
	obj->db = db;

	return obj;
}

static struct backend_obj *fs_obj_new(struct server_volume *vol,
				      struct database *db)
{
	struct fs_obj *obj;
	char *fn = NULL;
	uint64_t counter = 0xdeadbeef;
	char counterstr[32];

	obj = fs_obj_alloc(vol, db);
	if (!obj)
		return NULL;

	while (obj->out_fd < 0) {
		counter = next_counter();

		free(fn);

		sprintf(counterstr, "%016llX", (unsigned long long) counter);

		if (asprintf(&fn, "%s/%s", vol->path, counterstr) < 0) {
			syslog(LOG_ERR, "OOM in object_put");
			free(obj);
			return NULL;
		}

		obj->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}

	obj->out_fn = fn;
	strcpy(obj->bo.cookie, counterstr);

	return &obj->bo;
}

static struct backend_obj *fs_obj_open(struct server_volume *vol,
				       struct database *db,
				       const char *cookie,
				       enum errcode *err_code)
{
	struct fs_obj *obj;
	sqlite3_stmt *stmt;
	struct stat st;
	int rc;

	*err_code = InternalError;

	obj = fs_obj_alloc(vol, db);
	if (!obj)
		return NULL;

	stmt = obj->db->prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, vol->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, cookie, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		*err_code = NoSuchKey;
		sqlite3_reset(stmt);
		goto err_out;
	}

	strcpy(obj->bo.hashstr, (const char *) sqlite3_column_text(stmt, 1));

	sqlite3_reset(stmt);

	if (asprintf(&obj->in_fn, "%s/%s", vol->path, cookie) < 0)
		goto err_out;

	obj->in_fd = open(obj->in_fn, O_RDONLY);
	if (obj->in_fd < 0) {
		syslog(LOG_ERR, "open obj(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		goto err_out_fn;
	}

	if (fstat(obj->in_fd, &st) < 0) {
		syslog(LOG_ERR, "fstat obj(%s) failed: %s", obj->in_fn,
			strerror(errno));
		goto err_out_fd;
	}

	obj->bo.size = st.st_size;
	obj->bo.mtime = st.st_mtime;

	return &obj->bo;

err_out_fd:
	close(obj->in_fd);
err_out_fn:
	free(obj->in_fn);
err_out:
	free(obj);
	return NULL;
}

static void fs_obj_free(struct backend_obj *bo)
{
	struct fs_obj *obj = bo->private;

	if (!bo)
		return;

	if (obj->out_fn) {
		unlink(obj->out_fn);
		free(obj->out_fn);
	}

	if (obj->out_fd >= 0)
		close(obj->out_fd);

	if (obj->in_fn)
		free(obj->in_fn);
	if (obj->in_fd >= 0)
		close(obj->in_fd);

	free(obj);
}

static ssize_t fs_obj_read(struct backend_obj *bo, void *ptr, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	rc = read(obj->in_fd, ptr, len);
	if (rc < 0)
		syslog(LOG_ERR, "obj read(%s) failed: %s",
		       obj->in_fn, strerror(errno));

	return rc;
}

static ssize_t fs_obj_write(struct backend_obj *bo, const void *ptr,
			    size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	rc = write(obj->out_fd, ptr, len);
	if (rc < 0)
		syslog(LOG_ERR, "obj write(%s) failed: %s",
		       obj->out_fn, strerror(errno));

	return rc;
}

static bool fs_obj_write_commit(struct backend_obj *bo, const char *user,
				const char *hashstr)
{
	struct fs_obj *obj = bo->private;
	sqlite3_stmt *stmt;
	int rc;

	if (fsync(obj->out_fd) < 0) {
		syslog(LOG_ERR, "fsync(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	if (debugging) {
		struct stat sst;
		if (fstat(obj->out_fd, &sst) < 0)
			syslog(LOG_ERR, "fstat(%s) failed: %s",
			       obj->out_fn, strerror(errno));
		else
			syslog(LOG_DEBUG, "STORED %s, size %llu",
			       obj->out_fn,
			       (unsigned long long) sst.st_size);
	}

	close(obj->out_fd);
	obj->out_fd = -1;

	/* begin trans */
	if (!sql_begin(obj->db)) {
		syslog(LOG_ERR, "SQL BEGIN failed in put-end");
		return false;
	}

	/* insert object */
	stmt = obj->db->prep_stmts[st_add_obj];
	sqlite3_bind_text(stmt, 1, obj->bo.vol->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, hashstr, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, obj->bo.cookie, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, user, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL INSERT(obj) failed");
		goto err_out_rb;
	}

	/* commit */
	if (!sql_commit(obj->db)) {
		syslog(LOG_ERR, "SQL COMMIT");
		return false;
	}

	free(obj->out_fn);
	obj->out_fn = NULL;

	return true;

err_out_rb:
	sql_rollback(obj->db);
	return false;
}


static struct backend_info fs_info = {
	.name			= BE_NAME,
	.obj_new		= fs_obj_new,
	.obj_open		= fs_obj_open,
	.obj_read		= fs_obj_read,
	.obj_write		= fs_obj_write,
	.obj_write_commit	= fs_obj_write_commit,
	.obj_free		= fs_obj_free,
};

int be_fs_init(void)
{
	uint64_t r1 = rand();
	uint64_t r2 = rand();
	global_counter = (r1 << 32) | (r2 & 0xffffffff);

	return register_storage(&fs_info);
}

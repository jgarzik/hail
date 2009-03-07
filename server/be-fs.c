
#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
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
};

static struct fs_obj *fs_obj_alloc(struct server_volume *vol)
{
	struct fs_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	obj->bo.private = obj;
	obj->bo.vol = vol;

	obj->out_fd = -1;
	obj->in_fd = -1;

	return obj;
}

char *fs_obj_pathname(struct server_volume *vol, const char *cookie)
{
	char *s = NULL;

	if (asprintf(&s, "%s/%s", vol->path, cookie) < 0)
		return NULL;
	
	return s;
}

static bool cookie_valid(const char *cookie)
{
	int len = 0;

	/* empty strings are not valid cookies */
	if (!cookie || !*cookie)
		return false;

	/* cookies MUST consist of 100% lowercase hex digits */
	while (*cookie) {
		switch (*cookie) {
		case '0' ... '9':
		case 'a' ... 'f':
			cookie++;
			len++;
			break;

		default:
			return false;
		}
	}

	if (len < STD_COOKIE_MIN)
		return false;

	return true;
}

static struct backend_obj *fs_obj_new(struct server_volume *vol,
				      const char *cookie)
{
	struct fs_obj *obj;
	char *fn = NULL;
	struct be_fs_obj_hdr hdr;
	ssize_t wrc;

	memset(&hdr, 0, sizeof(hdr));

	if (!cookie_valid(cookie))
		return NULL;

	obj = fs_obj_alloc(vol);
	if (!obj)
		return NULL;

	/* build local fs pathname, volume path + cookie */
	fn = fs_obj_pathname(vol, cookie);
	if (!fn) {
		syslog(LOG_ERR, "OOM in object_put");
		goto err_out;
	}

	obj->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (obj->out_fd < 0) {
		if (errno != EEXIST)
			syslogerr(fn);
		goto err_out;
	}

	/* write object header */
	wrc = write(obj->out_fd, &hdr, sizeof(hdr));
	if (wrc != sizeof(hdr)) {
		if (wrc < 0)
			syslog(LOG_ERR, "obj hdr write(%s) failed: %s",
				fn, strerror(errno));
		else
			syslog(LOG_ERR, "obj hdr write(%s) failed for %s",
				fn, "unknown raisins!!!");
		goto err_out;
	}

	obj->out_fn = fn;
	strcpy(obj->bo.cookie, cookie);

	return &obj->bo;

err_out:
	free(obj);
	return NULL;
}

static struct backend_obj *fs_obj_open(struct server_volume *vol,
				       const char *cookie,
				       enum errcode *err_code)
{
	struct fs_obj *obj;
	struct stat st;
	struct be_fs_obj_hdr hdr;
	ssize_t rrc;

	if (!cookie_valid(cookie))
		return NULL;

	*err_code = InternalError;

	obj = fs_obj_alloc(vol);
	if (!obj)
		return NULL;

	/* build local fs pathname, volume path + cookie */
	obj->in_fn = fs_obj_pathname(vol, cookie);
	if (!obj->in_fn)
		goto err_out;

	obj->in_fd = open(obj->in_fn, O_RDONLY);
	if (obj->in_fd < 0) {
		syslog(LOG_ERR, "open obj(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		if (errno == ENOENT)
			*err_code = NoSuchKey;
		goto err_out_fn;
	}

	if (fstat(obj->in_fd, &st) < 0) {
		syslog(LOG_ERR, "fstat obj(%s) failed: %s", obj->in_fn,
			strerror(errno));
		goto err_out_fd;
	}

	/* read object header */
	rrc = read(obj->in_fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		if (rrc < 0)
			syslog(LOG_ERR, "read hdr obj(%s) failed: %s",
				obj->in_fn, strerror(errno));
		else
			syslog(LOG_ERR, "invalid object header for %s",
				obj->in_fn);
		goto err_out_fd;
	}

	strncpy(obj->bo.hashstr, hdr.checksum, sizeof(obj->bo.hashstr));
	obj->bo.hashstr[sizeof(obj->bo.hashstr) - 1] = 0;
	obj->bo.size = st.st_size - sizeof(hdr);
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
	struct fs_obj *obj;

	if (!bo)
		return;

	obj = bo->private;
	g_assert(obj != NULL);

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
				const char *hashstr, bool sync_data)
{
	struct fs_obj *obj = bo->private;
	struct be_fs_obj_hdr hdr;
	ssize_t wrc;

	memset(&hdr, 0, sizeof(hdr));
	strncpy(hdr.checksum, hashstr, sizeof(hdr.checksum));
	strncpy(hdr.owner, user, sizeof(hdr.owner));

	/* go back to beginning of file */
	if (lseek(obj->out_fd, 0, SEEK_SET) < 0) {
		syslog(LOG_ERR, "lseek(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	/* write final object header */
	wrc = write(obj->out_fd, &hdr, sizeof(hdr));
	if (wrc != sizeof(hdr)) {
		if (wrc < 0)
			syslog(LOG_ERR, "obj hdr write(%s) failed: %s",
				obj->out_fn, strerror(errno));
		else
			syslog(LOG_ERR, "obj hdr write(%s) failed for %s",
				obj->out_fn, "unknown raisins!!!");
		return false;
	}

	/* sync data to disk, if requested */
	if (sync_data && fsync(obj->out_fd) < 0) {
		syslog(LOG_ERR, "fsync(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	close(obj->out_fd);
	obj->out_fd = -1;

	free(obj->out_fn);
	obj->out_fn = NULL;

	return true;
}

static bool fs_obj_delete(struct server_volume *vol,
			  const char *cookie, enum errcode *err_code)
{
	char *fn = NULL;

	*err_code = InternalError;

	/* FIXME: check owner */

	/* build local fs pathname, volume path + cookie */
	fn = fs_obj_pathname(vol, cookie);
	if (!fn)
		goto err_out;

	if (unlink(fn) < 0) {
		if (errno == ENOENT)
			*err_code = NoSuchKey;
		else
			syslog(LOG_ERR, "object data(%s) unlink failed: %s",
			       fn, strerror(errno));
		goto err_out;
	}

	free(fn);
	return true;

err_out:
	free(fn);
	return false;
}

static GList *fs_list_objs(struct server_volume *vol)
{
	GList *res = NULL;
	struct dirent *de;
	DIR *d;

	d = opendir(vol->path);
	if (!d) {
		syslogerr(vol->path);
		return NULL;
	}

	/* iterate through each returned SQL data row */
	while ((de = readdir(d)) != NULL) {
		int fd;
		char *fn;
		ssize_t rrc;
		struct be_fs_obj_hdr hdr;

		if (de->d_name[0] == '.')
			continue;

		fn = fs_obj_pathname(vol, de->d_name);
		if (!fn)
			break;

		fd = open(fn, O_RDONLY);
		if (fd < 0) {
			syslogerr(fn);
			free(fn);
			break;
		}

		rrc = read(fd, &hdr, sizeof(hdr));
		if (rrc != sizeof(hdr)) {
			if (rrc < 0)
				syslogerr(fn);
			else
				syslog(LOG_ERR, "%s hdr read failed", fn);
			free(fn);
			break;
		}

		if (close(fd) < 0)
			syslogerr(fn);

		free(fn);

		res = g_list_append(res, strdup(de->d_name));
		res = g_list_append(res, strdup(hdr.checksum));
	}

	closedir(d);

	return res;
}

static struct backend_info fs_info = {
	.name			= BE_NAME,
	.obj_new		= fs_obj_new,
	.obj_open		= fs_obj_open,
	.obj_read		= fs_obj_read,
	.obj_write		= fs_obj_write,
	.obj_write_commit	= fs_obj_write_commit,
	.obj_delete		= fs_obj_delete,
	.obj_free		= fs_obj_free,
	.list_objs		= fs_list_objs,
};

int be_fs_init(void)
{
	return register_storage(&fs_info);
}

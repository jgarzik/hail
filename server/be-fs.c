
#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#if defined(HAVE_SYS_SENDFILE_H)
#include <sys/sendfile.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "chunkd.h"

#define BE_NAME		"fs"

struct fs_obj {
	struct backend_obj	bo;

	int			out_fd;
	char			*out_fn;

	int			in_fd;
	char			*in_fn;
	off_t			sendfile_ofs;
};

struct be_fs_obj_hdr {
	char			checksum[128];
	char			owner[128];
	uint32_t		key_len;
};

static struct fs_obj *fs_obj_alloc(void)
{
	struct fs_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	obj->bo.private = obj;

	obj->out_fd = -1;
	obj->in_fd = -1;

	return obj;
}

static char *fs_obj_pathname(const void *key, size_t key_len)
{
	char *s = NULL;
	char prefix[5] = "";
	struct stat st;
	size_t slen;
	unsigned char md[SHA256_DIGEST_LENGTH];
	char mdstr[(SHA256_DIGEST_LENGTH * 2) + 1];

	SHA256(key, key_len, md);
	hexstr(md, SHA256_DIGEST_LENGTH, mdstr);

	memcpy(prefix, mdstr, 4);

	slen = strlen(chunkd_srv.vol_path) + 1 + 
	       strlen(prefix) + 1 +
	       strlen(mdstr) + 1;
	s = malloc(slen);
	if (!s)
		return NULL;

	sprintf(s, "%s/%s", chunkd_srv.vol_path, prefix);

	/* create subdir on the fly, if not already exists */
	if (stat(s, &st) < 0) {
		if (errno == ENOENT) {
			if (mkdir(s, 0777) < 0) {
				syslogerr(s);

				/* Directory already exists, perhaps
				 * because we raced with another thread.
				 */
				if (errno != EEXIST)
					goto err_out;
			}
		} else {
			syslogerr(s);
			goto err_out;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		applog(LOG_WARNING, "%s: not a dir, fs_obj_pathname go boom", s);
		goto err_out;
	}

	sprintf(s, "%s/%s/%s", chunkd_srv.vol_path, prefix, mdstr + 4);

	return s;

err_out:
	free(s);
	return NULL;
}

static bool key_valid(const void *key, size_t key_len)
{
	if (!key || key_len < 1 || key_len > CHD_KEY_SZ)
		return false;
	
	return true;
}

struct backend_obj *fs_obj_new(const void *key, size_t key_len,
			       enum chunk_errcode *err_code)
{
	struct fs_obj *obj;
	char *fn = NULL;
	struct be_fs_obj_hdr hdr;
	ssize_t wrc;

	memset(&hdr, 0, sizeof(hdr));

	if (!key_valid(key, key_len)) {
		*err_code = che_InvalidKey;
		return NULL;
	}

	obj = fs_obj_alloc();
	if (!obj) {
		*err_code = che_InternalError;
		return NULL;
	}

	/* build local fs pathname */
	fn = fs_obj_pathname(key, key_len);
	if (!fn) {
		applog(LOG_ERR, "OOM in object_put");
		*err_code = che_InternalError;
		goto err_out;
	}

	obj->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (obj->out_fd < 0) {
		if (errno != EEXIST) {
			syslogerr(fn);
			*err_code = che_InternalError;
		} else {
			*err_code = che_NoSuchKey;
		}
		goto err_out;
	}

	/* write fixed-length portion of object header */
	wrc = write(obj->out_fd, &hdr, sizeof(hdr));
	if (wrc != sizeof(hdr)) {
		if (wrc < 0)
			applog(LOG_ERR, "obj hdr write(%s) failed: %s",
				fn, strerror(errno));
		else
			applog(LOG_ERR, "obj hdr write(%s) failed for %s",
				fn, "unknown raisins!!!");
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	/* write variable-length portion of object header */
	wrc = write(obj->out_fd, key, key_len);
	if (wrc != key_len) {
		if (wrc < 0)
			applog(LOG_ERR, "obj hdr key write(%s) failed: %s",
				fn, strerror(errno));
		else
			applog(LOG_ERR, "obj hdr key write(%s) failed for %s",
				fn, "unknown raisins!!!");
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	obj->out_fn = fn;
	obj->bo.key = g_memdup(key, key_len);
	obj->bo.key_len = key_len;

	return &obj->bo;

err_out_fd:
	close(obj->out_fd);
err_out:
	free(fn);
	free(obj);
	return NULL;
}

struct backend_obj *fs_obj_open(const char *user, const void *key,
				size_t key_len, enum chunk_errcode *err_code)
{
	struct fs_obj *obj;
	struct stat st;
	struct be_fs_obj_hdr hdr;
	ssize_t rrc;

	if (!key_valid(key, key_len)) {
		*err_code = che_InvalidKey;
		return NULL;
	}

	obj = fs_obj_alloc();
	if (!obj) {
		*err_code = che_InternalError;
		return NULL;
	}

	/* build local fs pathname */
	obj->in_fn = fs_obj_pathname(key, key_len);
	if (!obj->in_fn) {
		*err_code = che_InternalError;
		goto err_out;
	}

	obj->in_fd = open(obj->in_fn, O_RDONLY);
	if (obj->in_fd < 0) {
		applog(LOG_ERR, "open obj(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		if (errno == ENOENT)
			*err_code = che_NoSuchKey;
		else
			*err_code = che_InternalError;
		goto err_out_fn;
	}

	if (fstat(obj->in_fd, &st) < 0) {
		applog(LOG_ERR, "fstat obj(%s) failed: %s", obj->in_fn,
			strerror(errno));
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	/* read object fixed-length header */
	rrc = read(obj->in_fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		if (rrc < 0)
			applog(LOG_ERR, "read hdr obj(%s) failed: %s",
				obj->in_fn, strerror(errno));
		else
			applog(LOG_ERR, "invalid object header for %s",
				obj->in_fn);
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	/* authenticated user must own this object */
	if (strcmp(hdr.owner, user)) {
		*err_code = che_AccessDenied;
		goto err_out_fd;
	}

	/* verify object key length matches input key length */
	if (GUINT32_FROM_LE(hdr.key_len) != key_len) {
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	obj->bo.key = malloc(key_len);
	obj->bo.key_len = key_len;
	if (!obj->bo.key) {
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	/* read object variable-length header */
	rrc = read(obj->in_fd, obj->bo.key, key_len);
	if ((rrc != key_len) || (memcmp(key, obj->bo.key, key_len))) {
		if (rrc < 0)
			applog(LOG_ERR, "read hdr key obj(%s) failed: %s",
				obj->in_fn, strerror(errno));
		else
			applog(LOG_ERR, "invalid object header key for %s",
				obj->in_fn);
		*err_code = che_InternalError;
		goto err_out_fd;
	}

	strncpy(obj->bo.hashstr, hdr.checksum, sizeof(obj->bo.hashstr));
	obj->bo.hashstr[sizeof(obj->bo.hashstr) - 1] = 0;
	obj->bo.size = st.st_size - sizeof(hdr) - key_len;
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

void fs_obj_free(struct backend_obj *bo)
{
	struct fs_obj *obj;

	if (!bo)
		return;

	obj = bo->private;
	g_assert(obj != NULL);

	if (bo->key)
		free(bo->key);

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

ssize_t fs_obj_read(struct backend_obj *bo, void *ptr, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	rc = read(obj->in_fd, ptr, len);
	if (rc < 0)
		applog(LOG_ERR, "obj read(%s) failed: %s",
		       obj->in_fn, strerror(errno));

	return rc;
}

ssize_t fs_obj_write(struct backend_obj *bo, const void *ptr, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	rc = write(obj->out_fd, ptr, len);
	if (rc < 0)
		applog(LOG_ERR, "obj write(%s) failed: %s",
		       obj->out_fn, strerror(errno));

	return rc;
}

#if defined(HAVE_SENDFILE) && defined(__linux__)

ssize_t fs_obj_sendfile(struct backend_obj *bo, int out_fd, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	if (obj->sendfile_ofs == 0) {
		obj->sendfile_ofs += sizeof(struct be_fs_obj_hdr);
		obj->sendfile_ofs += bo->key_len;
	}

	rc = sendfile(out_fd, obj->in_fd, &obj->sendfile_ofs, len);
	if (rc < 0)
		applog(LOG_ERR, "obj sendfile(%s) failed: %s",
		       obj->in_fn, strerror(errno));

	return rc;
}

#elif defined(HAVE_SENDFILE) && defined(__FreeBSD__)

ssize_t fs_obj_sendfile(struct backend_obj *bo, int out_fd, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;
	off_t sbytes = 0;

	if (obj->sendfile_ofs == 0) {
		obj->sendfile_ofs += sizeof(struct be_fs_obj_hdr);
		obj->sendfile_ofs += bo->key_len;
	}

	rc = sendfile(obj->in_fd, out_fd, obj->sendfile_ofs, len,
		      NULL, &sbytes, 0);
	if (rc < 0) {
		applog(LOG_ERR, "obj sendfile(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		return rc;
	}

	obj->sendfile_ofs += sbytes;

	return sbytes;
}

#else

ssize_t fs_obj_sendfile(struct backend_obj *bo, int out_fd, size_t len)
{
	applog(LOG_ERR, "BUG: sendfile used but not supported");
	return -EOPNOTSUPP;
}

#endif /* HAVE_SENDFILE && HAVE_SYS_SENDFILE_H */

bool fs_obj_write_commit(struct backend_obj *bo, const char *user,
				const char *hashstr, bool sync_data)
{
	struct fs_obj *obj = bo->private;
	struct be_fs_obj_hdr hdr;
	ssize_t wrc;

	memset(&hdr, 0, sizeof(hdr));
	strncpy(hdr.checksum, hashstr, sizeof(hdr.checksum));
	strncpy(hdr.owner, user, sizeof(hdr.owner));
	hdr.key_len = GUINT32_TO_LE(bo->key_len);

	/* go back to beginning of file */
	if (lseek(obj->out_fd, 0, SEEK_SET) < 0) {
		applog(LOG_ERR, "lseek(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	/* write final object header */
	wrc = write(obj->out_fd, &hdr, sizeof(hdr));
	if (wrc != sizeof(hdr)) {
		if (wrc < 0)
			applog(LOG_ERR, "obj hdr write(%s) failed: %s",
				obj->out_fn, strerror(errno));
		else
			applog(LOG_ERR, "obj hdr write(%s) failed for %s",
				obj->out_fn, "unknown raisins!!!");
		return false;
	}

	/* sync data to disk, if requested */
	if (sync_data && fsync(obj->out_fd) < 0) {
		applog(LOG_ERR, "fsync(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	close(obj->out_fd);
	obj->out_fd = -1;

	free(obj->out_fn);
	obj->out_fn = NULL;

	return true;
}

bool fs_obj_delete(const char *user, const void *key, size_t key_len,
		   enum chunk_errcode *err_code)
{
	char *fn = NULL;
	int fd;
	ssize_t rrc;
	struct be_fs_obj_hdr hdr;

	*err_code = che_InternalError;

	if (!key_valid(key, key_len)) {
		*err_code = che_InvalidKey;
		return false;
	}

	/* build local fs pathname */
	fn = fs_obj_pathname(key, key_len);
	if (!fn)
		goto err_out;

	/* attempt to open object */
	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			*err_code = che_NoSuchKey;
		else
			applog(LOG_ERR, "object data(%s) open failed: %s",
			       fn, strerror(errno));
		goto err_out;
	}

	/* read object header */
	rrc = read(fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		if (rrc < 0)
			applog(LOG_ERR, "read hdr obj(%s) failed: %s",
				fn, strerror(errno));
		else
			applog(LOG_ERR, "invalid object header for %s", fn);
		goto err_out_fd;
	}

	/* close object */
	if (close(fd) < 0) {
		applog(LOG_ERR, "close hdr obj(%s) failed: %s",
			fn, strerror(errno));
		goto err_out;
	}

	/* verify authenticated user owns this object */
	if (strcmp(user, hdr.owner)) {
		*err_code = che_AccessDenied;
		goto err_out;
	}

	/* finally, unlink object */
	if (unlink(fn) < 0) {
		if (errno == ENOENT)
			*err_code = che_NoSuchKey;
		else
			applog(LOG_ERR, "object data(%s) unlink failed: %s",
			       fn, strerror(errno));
		goto err_out;
	}

	free(fn);
	return true;

err_out_fd:
	close(fd);
err_out:
	free(fn);
	return false;
}

GList *fs_list_objs(const char *user)
{
	GList *res = NULL;
	struct dirent *de, *root_de;
	DIR *d, *root;
	char *sub;

	sub = alloca(strlen(chunkd_srv.vol_path) + 1 + 4 + 1);

	root = opendir(chunkd_srv.vol_path);
	if (!root) {
		syslogerr(chunkd_srv.vol_path);
		return NULL;
	}

	/* iterate through each dir */
	while ((root_de = readdir(root)) != NULL) {

		if (root_de->d_name[0] == '.')
			continue;
		if (strlen(root_de->d_name) != 4)
			continue;

		sprintf(sub, "%s/%s", chunkd_srv.vol_path, root_de->d_name);
		d = opendir(sub);
		if (!d) {
			syslogerr(sub);
			break;
		}

		while ((de = readdir(d)) != NULL) {
			int fd;
			char *fn;
			ssize_t rrc;
			struct be_fs_obj_hdr hdr;
			struct stat st;
			struct volume_entry *ve;
			void *p;
			size_t alloc_len;
			void *key_in;
			uint32_t key_len_in;

			if (de->d_name[0] == '.')
				continue;

			if (asprintf(&fn, "%s/%s", sub, de->d_name) < 0)
				break;

			fd = open(fn, O_RDONLY);
			if (fd < 0) {
				syslogerr(fn);
				free(fn);
				break;
			}

			if (fstat(fd, &st) < 0) {
				syslogerr(fn);
				close(fd);
				free(fn);
				break;
			}

			rrc = read(fd, &hdr, sizeof(hdr));
			if (rrc != sizeof(hdr)) {
				if (rrc < 0)
					syslogerr(fn);
				else
					applog(LOG_ERR, "%s hdr read failed", fn);
				close(fd);
				free(fn);
				break;
			}

			key_len_in = GUINT32_FROM_LE(hdr.key_len);
			if (key_len_in < 1 || key_len_in > CHD_KEY_SZ) {
				applog(LOG_ERR, "%s hdr key len invalid", fn);
				close(fd);
				free(fn);
				break;
			}

			key_in = malloc(key_len_in);
			if (!key_in) {
				close(fd);
				free(fn);
				break;
			}

			rrc = read(fd, key_in, key_len_in);
			if (rrc != key_len_in) {
				if (rrc < 0)
					syslogerr(fn);
				else
					applog(LOG_ERR, "%s hdr read failed", fn);
				close(fd);
				free(fn);
				free(key_in);
				break;
			}

			if (close(fd) < 0)
				syslogerr(fn);

			free(fn);

			/* filter out results that do not match
			 * the authenticated user
			 */
			if (strcmp(user, hdr.owner))
				continue;

			/* one alloc, for fixed + var length struct */
			alloc_len = sizeof(*ve) +
				    strlen(hdr.checksum) + 1 +
				    strlen(hdr.owner) + 1;

			ve = malloc(alloc_len);
			if (!ve) {
				applog(LOG_ERR, "OOM");
				break;
			}

			/* store fixed-length portion of struct */
			st.st_size -= sizeof(struct be_fs_obj_hdr);
			st.st_size -= key_len_in;

			ve->size = st.st_size;
			ve->mtime = st.st_mtime;
			ve->key = key_in;
			ve->key_len = key_len_in;

			/*
			 * store variable-length portion of struct:
			 * checksum, owner strings
			 */

			p = (ve + 1);
			ve->hash = p;
			strcpy(ve->hash, hdr.checksum);

			p += strlen(ve->hash) + 1;
			ve->owner = p;
			strcpy(ve->owner, hdr.owner);

			/* add entry to result list */
			res = g_list_append(res, ve);
		}

		closedir(d);
	}

	closedir(root);

	return res;
}


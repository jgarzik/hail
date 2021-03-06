
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
#define _FILE_OFFSET_BITS 64
#include "hail-config.h"

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
#include <tcutil.h>
#include <tchdb.h>
#include <chunk-private.h>
#include "chunkd.h"

#define BE_FS_OBJ_MAGIC		"CHU1"

struct fs_obj {
	struct backend_obj	bo;

	int			out_fd;
	char			*out_fn;
	uint64_t		written_bytes;

	int			in_fd;
	char			*in_fn;
	off_t			in_pos;
	off_t			sendfile_ofs;

	off_t			value_ofs;

	off_t			tail_pos;
	size_t			tail_len;

	size_t			checked_bytes;
	SHA_CTX			checksum;
	unsigned int		csum_idx;
	void			*csum_tbl;
	size_t			csum_tbl_sz;

	unsigned int		n_blk;
};

struct be_fs_obj_hdr {
	char			magic[4];
	uint32_t		key_len;
	uint64_t		value_len;
	uint32_t		n_blk;

	char			reserved[12];

	unsigned char		hash[CHD_CSUM_SZ];
	char			owner[128];
} __attribute__ ((packed));

int fs_open(void)
{
	TCHDB *hdb;
	char *db_fn = NULL;
	int rc = 0, omode;

	if (asprintf(&db_fn, "%s/master.tch", chunkd_srv.vol_path) < 0)
		return -ENOMEM;

	hdb = tchdbnew();
	if (!hdb) {
		rc = -ENOMEM;
		goto out;
	}

	if (!tchdbsetmutex(hdb))
		goto out_mut;

	omode = HDBOREADER | HDBONOLCK | HDBOWRITER | HDBOCREAT | HDBOTSYNC;
	if (!tchdbopen(hdb, db_fn, omode)) {
		applog(LOG_ERR, "failed to open master table %s", db_fn);
		rc = -EIO;
		goto out_hdb;
	}

	chunkd_srv.tbl_master = hdb;

	free(db_fn);
	return 0;

out_mut:
out_hdb:
	tchdbdel(hdb);
out:
	free(db_fn);
	return rc;
}

void fs_close(void)
{
	tchdbclose(chunkd_srv.tbl_master);
}

void fs_free(void)
{
	if (chunkd_srv.tbl_master)
		tchdbdel(chunkd_srv.tbl_master);
}

bool fs_table_open(const char *user, const void *kbuf, size_t klen,
		   bool tbl_creat, bool excl_creat, uint32_t *table_id,
		   enum chunk_errcode *err_code)
{
	TCHDB *hdb = chunkd_srv.tbl_master;
	char *table_path = NULL;
	int osize = 0, next_num;
	bool rc = false;
	uint32_t *val_p, table_id_le;

	*err_code = che_InternalError;

	if (!tbl_creat && excl_creat) {
		*err_code = che_InvalidArgument;
		return false;
	}

	/* validate table name */
	if (klen < 1 || klen > CHD_KEY_SZ ||
	    (klen >= strlen(MDB_TABLE_ID) &&
	     !memcmp(kbuf, MDB_TABLE_ID, strlen(MDB_TABLE_ID)))) {
		*err_code = che_InvalidArgument;
		return false;
	}

	/*
	 * lookup table name.  if found, return immediately
	 */
	val_p = tchdbget(hdb, kbuf, klen, &osize);
	if (val_p) {
		if (tbl_creat && excl_creat) {
			*err_code = che_InvalidArgument;
			goto out_close;
		}

		*table_id = GUINT32_FROM_LE(*val_p);
		goto out_ok;
	}

	/*
	 * otherwise, we now begin the process of table creation
	 */

	if (!tbl_creat) {
		*err_code = che_InvalidArgument;
		goto out_close;
	}

	/* allocate unique integer id for table */
	next_num = tchdbaddint(hdb, MDB_TABLE_ID, strlen(MDB_TABLE_ID)+1, 1);
	if (next_num == INT_MIN)
		goto out_close;

	*table_id = next_num;
	table_id_le = GUINT32_TO_LE(next_num);

	/*
	 * create table directory, $BASE_PATH/table-id
	 */
	if (asprintf(&table_path, MDB_TPATH_FMT,
		     chunkd_srv.vol_path, next_num) < 0)
		goto out_close;

	if ((mkdir(table_path, 0777) < 0) && (errno != EEXIST)) {
		applog(LOG_ERR, "mkdir(%s): %s", table_path, strerror(errno));
		goto out_close;
	}

	/* finally, store in table_name->table_id map */
	if (!tchdbput(hdb, kbuf, klen, &table_id_le, sizeof(table_id_le)))
		goto out_close;

out_ok:
	*err_code = che_Success;
	rc = true;
out_close:
	free(table_path);
	return rc;
}

static struct fs_obj *fs_obj_alloc(void)
{
	struct fs_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	obj->bo.private = obj;

	obj->out_fd = -1;
	obj->in_fd = -1;

	SHA1_Init(&obj->checksum);

	return obj;
}

static char *fs_obj_pathname(uint32_t table_id,const void *key, size_t key_len)
{
	char *s = NULL;
	char prefix[PREFIX_LEN + 1] = "";
	struct stat st;
	size_t slen;
	unsigned char md[SHA256_DIGEST_LENGTH];
	char mdstr[(SHA256_DIGEST_LENGTH * 2) + 1];

	if (!table_id || !key || !key_len)
		return NULL;

	SHA256(key, key_len, md);
	hexstr(md, SHA256_DIGEST_LENGTH, mdstr);

	memcpy(prefix, mdstr, PREFIX_LEN);

	slen = strlen(chunkd_srv.vol_path) + 1 +	/* volume */
	       16 +					/* table id */
	       strlen(prefix) + 1 +			/* prefix */
	       strlen(mdstr) + 1;			/* filename */
	s = malloc(slen);
	if (!s)
		return NULL;

	sprintf(s, MDB_TPATH_FMT "/%s", chunkd_srv.vol_path, table_id, prefix);

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

	sprintf(s, MDB_TPATH_FMT "/%s/%s", chunkd_srv.vol_path, table_id,
		prefix, mdstr + PREFIX_LEN);

	return s;

err_out:
	free(s);
	return NULL;
}

static char *fs_obj_badname(unsigned long tag)
{
	char *s;
	struct stat st;
	int rc;

	rc = asprintf(&s, BAD_TPATH_FMT, chunkd_srv.vol_path);
	if (rc < 0)
		return NULL;

	/* create subdir on the fly, if not already exists */
	if (stat(s, &st) < 0) {
		if (errno != ENOENT) {
			syslogerr(s);
			free(s);
			return NULL;
		}
		if (mkdir(s, 0777) < 0) {
			if (errno != EEXIST) {
				syslogerr(s);
				free(s);
				return NULL;
			}
		}
	} else {
		if (!S_ISDIR(st.st_mode)) {
			applog(LOG_WARNING,
			       "%s: not a dir, fs_obj_badname go boom", s);
			free(s);
			return NULL;
		}
	}
	free(s);

	rc = asprintf(&s, BAD_TPATH_FMT "/%lu", chunkd_srv.vol_path, tag);
	if (rc < 0)
		return NULL;

	return s;
}

static bool key_valid(const void *key, size_t key_len)
{
	if (!key || key_len < 1 || key_len > CHD_KEY_SZ)
		return false;
	
	return true;
}

static unsigned int fs_blk_count(uint64_t data_len)
{
	uint64_t n_blk;

	n_blk = data_len >> CHUNK_BLK_ORDER;
	if (data_len & (CHUNK_BLK_SZ - 1))
		n_blk++;

	return (unsigned int) n_blk;
}

struct backend_obj *fs_obj_new(uint32_t table_id,
			       const void *key, size_t key_len,
			       uint64_t data_len,
			       enum chunk_errcode *err_code)
{
	struct fs_obj *obj;
	char *fn = NULL;
	size_t csum_bytes;
	enum chunk_errcode erc = che_InternalError;
	off_t skip_len;

	if (!key_valid(key, key_len)) {
		*err_code = che_InvalidKey;
		return NULL;
	}

	obj = fs_obj_alloc();
	if (!obj) {
		*err_code = che_InternalError;
		return NULL;
	}

	obj->n_blk = fs_blk_count(data_len);
	csum_bytes = obj->n_blk * CHD_CSUM_SZ;
	obj->csum_tbl = malloc(csum_bytes);
	if (!obj->csum_tbl)
		goto err_out;
	obj->csum_tbl_sz = csum_bytes;
	obj->tail_pos = data_len & ~(CHUNK_BLK_SZ - 1);
	obj->tail_len = data_len & (CHUNK_BLK_SZ - 1);

	/* build local fs pathname */
	fn = fs_obj_pathname(table_id, key, key_len);
	if (!fn)
		goto err_out;

	obj->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (obj->out_fd < 0) {
		if (errno != EEXIST)
			syslogerr(fn);
		else
			erc = che_KeyExists;
		goto err_out;
	}

	/* we cannot set ->out_fn immediately, because fs_obj_free +
	 * an error may trigger an erroneous unlink
	 */
	obj->out_fn = fn;

	/* calculate size of front-of-file metadata area */
	skip_len = sizeof(struct be_fs_obj_hdr) + key_len + csum_bytes;
	obj->value_ofs = skip_len;

	/* position file pointer where object data (as in, not metadata)
	 * will begin
	 */
	errno = 0;
	if (lseek(obj->out_fd, obj->value_ofs, SEEK_SET) != obj->value_ofs) {
		applog(LOG_ERR, "obj hdr seek(%s) failed: %s",
		       fn, strerror(errno));
		goto err_out;
	}

	obj->bo.key = g_memdup(key, key_len);
	if (!obj->bo.key)
		goto err_out;
	obj->bo.key_len = key_len;
	obj->bo.size = data_len;

	*err_code = che_Success;
	return &obj->bo;

err_out:
	if (!obj->out_fn)	/* avoid double-free */
		free(fn);
	fs_obj_free(&obj->bo);
	*err_code = erc;
	return NULL;
}

struct backend_obj *fs_obj_open(uint32_t table_id, const char *user,
				const void *key, size_t key_len,
				enum chunk_errcode *err_code)
{
	struct fs_obj *obj;
	struct stat st;
	struct be_fs_obj_hdr hdr;
	ssize_t rrc;
	uint64_t value_len, tmp64;
	size_t csum_bytes;
	enum chunk_errcode erc = che_InternalError;
	struct iovec iov[2];
	size_t total_rd_len;

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
	obj->in_fn = fs_obj_pathname(table_id, key, key_len);
	if (!obj->in_fn)
		goto err_out;

	obj->in_fd = open(obj->in_fn, O_RDONLY);
	if (obj->in_fd < 0) {
		applog(LOG_ERR, "open obj(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		if (errno == ENOENT)
			erc = che_NoSuchKey;
		goto err_out;
	}

	if (fstat(obj->in_fd, &st) < 0) {
		applog(LOG_ERR, "fstat obj(%s) failed: %s", obj->in_fn,
			strerror(errno));
		goto err_out;
	}

	/* read object fixed-length header */
	rrc = read(obj->in_fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		applog(LOG_ERR, "read hdr obj(%s) failed: %s",
			obj->in_fn,
			(rrc < 0) ? strerror(errno) : "<unknown reasons>");
		goto err_out;
	}

	/* verify magic number in header */
	if (G_UNLIKELY(memcmp(hdr.magic, BE_FS_OBJ_MAGIC,
		       strlen(BE_FS_OBJ_MAGIC)))) {
		applog(LOG_ERR, "obj(%s) hdr magic corrupted", obj->in_fn);
		goto err_out;
	}

	/* authenticated user must own this object */
	if (strcmp(hdr.owner, user)) {
		erc = che_AccessDenied;
		goto err_out;
	}

	/* verify object key length matches input key length */
	if (G_UNLIKELY(GUINT32_FROM_LE(hdr.key_len) != key_len))
		goto err_out;

	value_len = GUINT64_FROM_LE(hdr.value_len);
	obj->n_blk = GUINT32_FROM_LE(hdr.n_blk);
	csum_bytes = obj->n_blk * CHD_CSUM_SZ;
	obj->tail_pos = value_len & ~(CHUNK_BLK_SZ - 1);
	obj->tail_len = value_len & (CHUNK_BLK_SZ - 1);
	obj->value_ofs = sizeof(hdr) + key_len + csum_bytes;

	/* verify file size large enough to contain value */
	tmp64 = obj->value_ofs + value_len;
	if (G_UNLIKELY(st.st_size < tmp64)) {
		applog(LOG_ERR, "obj(%s) size error, too small", obj->in_fn);
		goto err_out;
	}

	/* verify expected size of checksum table */
	if (G_UNLIKELY(fs_blk_count(value_len) != obj->n_blk)) {
		applog(LOG_ERR, "obj(%s) unexpected blk count "
		       "(%u from val sz, %u from hdr)",
		       obj->in_fn, fs_blk_count(value_len), obj->n_blk);
		goto err_out;
	}

	obj->csum_tbl = malloc(csum_bytes);
	if (!obj->csum_tbl)
		goto err_out;
	obj->csum_tbl_sz = csum_bytes;

	obj->bo.key = malloc(key_len);
	obj->bo.key_len = key_len;
	if (!obj->bo.key)
		goto err_out;

	/* init additional header segment list */
	iov[0].iov_base = obj->bo.key;
	iov[0].iov_len = key_len;
	iov[1].iov_base = obj->csum_tbl;
	iov[1].iov_len = csum_bytes;
	total_rd_len = iov[0].iov_len + iov[1].iov_len;

	/* read additional header segments (key, checksum table) */
	rrc = readv(obj->in_fd, iov, ARRAY_SIZE(iov));
	if ((rrc != total_rd_len) || (memcmp(key, obj->bo.key, key_len))) {
		applog(LOG_ERR, "read addnl hdrs(%s) failed: %s",
			obj->in_fn,
			(rrc < 0) ? strerror(errno) : "<unknown reasons>");
		goto err_out;
	}

	memcpy(obj->bo.hash, hdr.hash, sizeof(obj->bo.hash));
	obj->bo.size = value_len;
	obj->bo.mtime = st.st_mtime;

	*err_code = che_Success;
	return &obj->bo;

err_out:
	fs_obj_free(&obj->bo);
	*err_code = erc;
	return NULL;
}

void fs_obj_free(struct backend_obj *bo)
{
	struct fs_obj *obj;

	if (!bo)
		return;

	obj = bo->private;
	g_assert(obj != NULL);

	free(bo->key);

	if (obj->out_fn) {
		unlink(obj->out_fn);
		free(obj->out_fn);
	}

	if (obj->out_fd >= 0)
		close(obj->out_fd);

	free(obj->in_fn);
	if (obj->in_fd >= 0)
		close(obj->in_fd);

	free(obj->csum_tbl);
	free(obj);
}

static bool can_csum_range(struct fs_obj *obj, size_t len)
{
	off_t want_pos, end_pos;

	if (len == 0)
		return false;

	/* we can csum a region, if the csum starts and ends on
	 * a block boundary
	 */

	/* if current position not aligned, fail */
	if (obj->in_pos & (CHUNK_BLK_SZ - 1))
		return false;

	end_pos = obj->tail_pos + obj->tail_len;
	want_pos = obj->in_pos + len;

	/* if request extends beyond known csum table, fail */
	if (want_pos > end_pos)
		return false;

	/* if ending position is aligned, succeed */
	if ((want_pos & (CHUNK_BLK_SZ - 1)) == 0)
		return true;

	/* if ending position is end of file, succeed */
	if (want_pos == end_pos)
		return true;
	
	/* otherwise, ending position is not aligned, fail */
	return false;
}

int fs_obj_seek(struct backend_obj *bo, uint64_t rel_ofs)
{
	struct fs_obj *obj = bo->private;
	uint64_t abs_ofs64 = obj->value_ofs + rel_ofs;
	off_t abs_ofs = abs_ofs64;
	off_t rc;

	rc = lseek(obj->in_fd, abs_ofs, SEEK_SET);
	if (rc == (off_t)-1) {
		applog(LOG_ERR, "obj seek(%s, %llu + %llu, SEEK_SET) failed: %s",
		       obj->in_fn,
		       (unsigned long long) obj->value_ofs,
		       (unsigned long long) rel_ofs,
		       strerror(errno));
		return -errno;
	}

	obj->in_pos = rc - obj->value_ofs;

	return 0;
}

ssize_t fs_obj_read(struct backend_obj *bo, void *ptr, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;
	unsigned int cur_blk, blk_idx, blk_cnt, last_blk;
	void *tmp_p;
	bool have_tail;

	/* read data from local storage */
	rc = read(obj->in_fd, ptr, len);
	if (rc == 0) {
		applog(LOG_WARNING, "obj read(%s) reached end of file: %s",
		       obj->in_fn);
		return 0;
	} else if (rc < 0) {
		applog(LOG_ERR, "obj read(%s) failed: %s",
		       obj->in_fn, strerror(errno));
		return -errno;
	}

	/* verify read alignment */
	if (!can_csum_range(obj, rc)) {
		applog(LOG_INFO, "obj(%s) unaligned read, 0x%x @ 0x%llx",
		       obj->in_fn, len,
		       (unsigned long long) obj->in_pos);
		goto out;
	}

	have_tail = (obj->tail_len > 0);
	cur_blk = fs_blk_count(obj->in_pos);
	last_blk = obj->n_blk - 1;
	blk_cnt = fs_blk_count(rc);
	tmp_p = ptr;

	/* verify checksum for each block read from local storage */
	for (blk_idx = cur_blk; blk_idx < (cur_blk + blk_cnt); blk_idx++) {
		unsigned char md[CHD_CSUM_SZ];
		unsigned int blk_len;
		int cmprc;

		if ((blk_idx == last_blk) && have_tail)
			blk_len = obj->tail_len;
		else
			blk_len = CHUNK_BLK_SZ;

		SHA1(tmp_p, blk_len, md);

		cmprc = memcmp(md, obj->csum_tbl + (blk_idx * CHD_CSUM_SZ),
			       CHD_CSUM_SZ);

		if (cmprc) {
			applog(LOG_WARNING, "obj(%s) csum failed @ %u blk",
			       obj->in_fn, blk_idx);
			return -EIO;
		}

		tmp_p += blk_len;
	}

out:
	obj->in_pos += rc;

	return rc;
}

static void obj_flush_csum(struct backend_obj *bo)
{
	struct fs_obj *obj = bo->private;
	unsigned char md[CHD_CSUM_SZ];

	if (G_UNLIKELY(obj->csum_idx >= obj->n_blk)) {
		applog(LOG_ERR, "BUG %s: cidx %u, n_blk %u",
		       __func__, obj->csum_idx, obj->n_blk);
		return;
	}

	SHA1_Final(md, &obj->checksum);

	memcpy(obj->csum_tbl + ((obj->csum_idx++) * CHD_CSUM_SZ),
	       md, CHD_CSUM_SZ);

	obj->checked_bytes = 0;
	SHA1_Init(&obj->checksum);
}

ssize_t fs_obj_write(struct backend_obj *bo, const void *ptr, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t total_written = 0;

	while (len > 0) {
		size_t unchecked;
		ssize_t wrc;

		unchecked = CHUNK_BLK_SZ - obj->checked_bytes;

		wrc = write(obj->out_fd, ptr, MIN(unchecked, len));
		if (wrc < 0) {
			applog(LOG_ERR, "obj write(%s) failed: %s",
			       obj->out_fn, strerror(errno));
			return wrc;
		}

		SHA1_Update(&obj->checksum, ptr, wrc);

		total_written += wrc;
		obj->written_bytes += wrc;
		obj->checked_bytes += wrc;
		ptr += wrc;
		len -= wrc;

		/* if at end of 64k block, update csum table with new csum */
		if (obj->checked_bytes == CHUNK_BLK_SZ)
			obj_flush_csum(bo);
	}

	return total_written;
}

#if defined(HAVE_SENDFILE) && defined(__linux__)

ssize_t fs_obj_sendfile(struct backend_obj *bo, int out_fd, size_t len)
{
	struct fs_obj *obj = bo->private;
	ssize_t rc;

	if (obj->sendfile_ofs == 0)
		obj->sendfile_ofs =
			sizeof(struct be_fs_obj_hdr) +
			bo->key_len +
			obj->csum_tbl_sz;

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

	if (obj->sendfile_ofs == 0)
		obj->sendfile_ofs =
			sizeof(struct be_fs_obj_hdr) +
			bo->key_len +
			obj->csum_tbl_sz;

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
			 unsigned char *md, bool sync_data)
{
	struct fs_obj *obj = bo->private;
	struct be_fs_obj_hdr hdr;
	ssize_t wrc;
	size_t total_wr_len;
	struct iovec iov[3];

	if (G_UNLIKELY(obj->bo.size != obj->written_bytes)) {
		applog(LOG_ERR, "BUG(%s): size/written_bytes mismatch: %llu/%llu",
		       obj->out_fn,
		       (unsigned long long) obj->bo.size,
		       (unsigned long long) obj->written_bytes);
		return false;
	}

	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.magic, BE_FS_OBJ_MAGIC, strlen(BE_FS_OBJ_MAGIC));
	memcpy(hdr.hash, md, sizeof(hdr.hash));
	strncpy(hdr.owner, user, sizeof(hdr.owner));
	hdr.key_len = GUINT32_TO_LE(bo->key_len);
	hdr.value_len = GUINT64_TO_LE(obj->written_bytes);
	hdr.n_blk = GUINT32_TO_LE(obj->n_blk);

	/* update checksum table with final csum, if necessary */
	if (obj->checked_bytes > 0)
		obj_flush_csum(bo);

	if (G_UNLIKELY(obj->csum_idx != obj->n_blk)) {
		applog(LOG_ERR, "BUG(%s): csum_idx/n_blk mismatch: %u/%u",
		       obj->out_fn, obj->csum_idx, obj->n_blk);
		return false;
	}

	obj->csum_idx = 0;

	/* go back to beginning of file */
	if (lseek(obj->out_fd, 0, SEEK_SET) < 0) {
		applog(LOG_ERR, "lseek(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	/* init header segment list */
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = bo->key;
	iov[1].iov_len = bo->key_len;
	iov[2].iov_base = obj->csum_tbl;
	iov[2].iov_len = obj->csum_tbl_sz;
	total_wr_len = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;

	/* write object header segments */
	wrc = writev(obj->out_fd, iov, ARRAY_SIZE(iov));
	if (wrc != total_wr_len) {
		applog(LOG_ERR, "obj hdr writev(%s) failed: %s",
		       obj->out_fn, (wrc < 0) ? strerror(errno) : "<unknown>");
		return false;
	}

	/* sync data to disk, if requested */
	if (sync_data && fsync(obj->out_fd) < 0) {
		applog(LOG_ERR, "fsync(%s) failed: %s",
		       obj->out_fn, strerror(errno));
		return false;
	}

	if (close(obj->out_fd) < 0)
		applog(LOG_WARNING, "close(%s) failed: %s",
		       obj->out_fn, strerror(errno));
	obj->out_fd = -1;

	free(obj->out_fn);
	obj->out_fn = NULL;

	obj->written_bytes = 0;

	return true;
}

bool fs_obj_delete(uint32_t table_id, const char *user,
		   const void *key, size_t key_len,
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
	fn = fs_obj_pathname(table_id, key, key_len);
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

	/* basic sanity check: verify magic number in header */
	if (G_UNLIKELY(memcmp(hdr.magic, BE_FS_OBJ_MAGIC,
			      strlen(BE_FS_OBJ_MAGIC)))) {
		*err_code = che_InternalError;
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

int fs_obj_disable(const char *fn)
{
	struct stat st;
	char *bad;
	int rc;

	if (stat(fn, &st) < 0)
		return -errno;

	bad = fs_obj_badname(st.st_ino);

	if (rename(fn, bad) < 0) {
		rc = errno;
		free(bad);
		return -rc;
	}

	free(bad);
	return 0;
}

int fs_list_objs_open(struct fs_obj_lister *t,
		      const char *root_path, uint32_t table_id)
{
	int err;

	if (asprintf(&t->table_path, MDB_TPATH_FMT, root_path, table_id) < 0)
		return -ENOMEM;
	t->root = opendir(t->table_path);
	if (!t->root) {
		err = errno;
		free(t->table_path);
		return -err;
	}
	return 0;
}

/*
 * Get next filename.
 * Return:
 * -1  - error
 *  0  - EOF
 *  1  - ok
 */
int fs_list_objs_next(struct fs_obj_lister *t, char **fnp)
{
	struct dirent *de;

again:
	if (!t->sub) {
		if ((de = readdir(t->root)) == NULL)
			return 0;

		if (de->d_name[0] == '.')
			goto again;
		if (strlen(de->d_name) != PREFIX_LEN)
			goto again;

		if (asprintf(&t->sub, "%s/%s", t->table_path, de->d_name) < 0)
			return -1;
	}

	if (!t->d) {
		t->d = opendir(t->sub);
		if (!t->d) {
			syslogerr(t->sub);
			free(t->sub);
			t->sub = NULL;
			goto again;
		}
	}

	if ((de = readdir(t->d)) == NULL) {
		closedir(t->d);
		t->d = NULL;
		free(t->sub);
		t->sub = NULL;
		goto again;
	}

	if (de->d_name[0] == '.')
		goto again;

	if (asprintf(fnp, "%s/%s", t->sub, de->d_name) < 0)
		return -1;

	return 1;
}

void fs_list_objs_close(struct fs_obj_lister *t)
{
	closedir(t->root);
	free(t->table_path);

	if (t->d)
		closedir(t->d);
	free(t->sub);
}

/*
 * Read an object by filename.
 * TODO - possibly factor out some code from fs_obj_open and fs_obj_delete.
 */
int fs_obj_hdr_read(const char *fn, char **owner, unsigned char *hash,
		    void **keyp, size_t *klenp, size_t *csumlenp,
		    unsigned long long *size, time_t *mtime)
{
	struct be_fs_obj_hdr hdr;
	struct stat st;
	int fd;
	ssize_t rrc;
	void *key_in;
	size_t klen_in;
	uint64_t vlen_in;

	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		syslogerr(fn);
		goto err_open;
	}

	if (fstat(fd, &st) < 0) {
		syslogerr(fn);
		goto err_stat;
	}

	rrc = read(fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		if (rrc < 0)
			syslogerr(fn);
		else
			applog(LOG_WARNING, "%s hdr read failed", fn);
		goto err_fix;
	}

	if (memcmp(hdr.magic, BE_FS_OBJ_MAGIC, strlen(BE_FS_OBJ_MAGIC))) {
		applog(LOG_WARNING, "%s hdr magic invalid", fn);
		goto err_fix;
	}

	klen_in = GUINT32_FROM_LE(hdr.key_len);
	if (klen_in < 1 || klen_in > CHD_KEY_SZ) {
		applog(LOG_WARNING, "%s hdr key len (0x%x) invalid",
		       fn, (unsigned int)klen_in);
		goto err_fix;
	}

	vlen_in = GUINT64_FROM_LE(hdr.value_len);
	if ((st.st_size - sizeof(hdr) - klen_in) < vlen_in) {
		applog(LOG_WARNING, "%s hdr value len (0x%llx) invalid",
		       fn, (unsigned long long)vlen_in);
		goto err_fix;
	}

	key_in = malloc(klen_in);
	if (!key_in) {
		applog(LOG_WARNING, "NO CORE");
		goto err_fix;
	}

	rrc = read(fd, key_in, klen_in);
	if (rrc != klen_in) {
		if (rrc < 0)
			syslogerr(fn);
		else
			applog(LOG_ERR, "%s hdr short read (%lu)",
			       fn, (unsigned long)rrc);
		goto err_var;
	}

	*csumlenp = GUINT32_FROM_LE(hdr.n_blk) * CHD_CSUM_SZ;

	*owner = strndup(hdr.owner, sizeof(hdr.owner));
	if (!*owner) {
		applog(LOG_WARNING, "NO CORE");
		goto err_owner;
	}

	memcpy(hash, hdr.hash, sizeof(hdr.hash));

	*keyp = key_in;
	*klenp = klen_in;
	*size = vlen_in;
	*mtime = st.st_mtime;

	close(fd);
	return 0;

 err_owner:
 err_var:
	free(key_in);
 err_fix:
 err_stat:
	close(fd);
 err_open:
	return -1;
}

GList *fs_list_objs(uint32_t table_id, const char *user)
{
	struct fs_obj_lister lister;
	GList *res = NULL;
	char *fn;
	int rc;

	memset(&lister, 0, sizeof(struct fs_obj_lister));
	rc = fs_list_objs_open(&lister, chunkd_srv.vol_path, table_id);
	if (rc) {
		applog(LOG_WARNING, "Cannot open table %u: %s", table_id,
		       strerror(-rc));
		return NULL;
	}

	while (fs_list_objs_next(&lister, &fn) > 0) {
		char *owner;
		unsigned long long size;
		time_t mtime;
		struct volume_entry *ve;
		void *p;
		unsigned char md[CHD_CSUM_SZ];
		size_t alloc_len;
		void *key_in;
		size_t klen_in, csumlen_in;
		char hashstr[(CHD_CSUM_SZ * 2) + 1];

		rc = fs_obj_hdr_read(fn, &owner, md, &key_in, &klen_in,
				     &csumlen_in, &size, &mtime);
		if (rc < 0) {
			free(fn);
			break;
		}
		free(fn);

		hexstr(md, CHD_CSUM_SZ, hashstr);

		/* filter out results that do not match
		 * the authenticated user
		 */
		if (strcmp(user, owner)) {
			free(owner);
			free(key_in);
			continue;
		}

		/* one alloc, for fixed + var length struct */
		alloc_len = sizeof(*ve) + strlen(hashstr)+1 + strlen(owner) + 1;

		ve = malloc(alloc_len);
		if (!ve) {
			free(owner);
			free(key_in);
			applog(LOG_ERR, "OOM");
			break;
		}

		/* store fixed-length portion of struct */
		ve->size = size;
		ve->mtime = mtime;
		ve->key = key_in;
		ve->key_len = klen_in;

		/*
		 * store variable-length portion of struct:
		 * checksum, owner strings
		 */

		p = (ve + 1);
		ve->hash = p;
		strcpy(ve->hash, hashstr);

		p += strlen(ve->hash) + 1;
		ve->owner = p;
		strcpy(ve->owner, owner);

		/* add entry to result list */
		res = g_list_append(res, ve);

		free(owner);
	}

	fs_list_objs_close(&lister);
	return res;
}

int fs_obj_do_sum(const char *fn, unsigned int klen, unsigned int csumlen,
		  unsigned char *md)
{
	enum { BUFLEN = 128 * 1024 };
	void *buf;
	int fd;
	ssize_t rrc;
	int rc;
	SHA_CTX hash;

	rc = ENOMEM;
	buf = malloc(BUFLEN);
	if (!buf)
		goto err_alloc;

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		rc = errno;
		goto err_open;
	}
	if (lseek(fd, sizeof(struct be_fs_obj_hdr) + klen + csumlen,
		  SEEK_SET) == (off_t)-1) {
		rc = errno;
		goto err_seek;
	}

	SHA1_Init(&hash);
	for (;;) {
		rrc = read(fd, buf, BUFLEN);
		if (rrc < 0) {
			rc = errno;
			goto err_read;
		}
		if (rrc != 0)
			SHA1_Update(&hash, buf, rrc);
		if (rrc < BUFLEN)
			break;
	}
	SHA1_Final(md, &hash);

	close(fd);
	free(buf);
	return 0;

 err_read:
	close(fd);
 err_seek:
 err_open:
	free(buf);
 err_alloc:
	return -rc;
}


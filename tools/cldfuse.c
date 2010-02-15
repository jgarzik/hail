
/*
 * Copyright 2010 Red Hat, Inc.
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

#define FUSE_USE_VERSION 26
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <glib.h>
#include <fuse.h>
#include <cldc.h>
#include <ncld.h>

#define TAG "cldfuse"

struct cldfuse_param {
	GList		*host_list;
};

static struct cldfuse_param param;
static struct ncld_sess *sess;

static void applog(int prio, const char *fmt, ...)
{
	char buf[200];
	va_list ap;

	va_start(ap, fmt);
	snprintf(buf, 200, TAG ": %s\n", fmt);
	vfprintf(stderr, buf, ap);
	va_end(ap);
}

static struct hail_log cldfuse_log = {
	.func		= applog,
	.verbose	= 0,
};

static void sess_event(void *private, uint32_t what)
{
	fprintf(stderr, "FIXME: handle event(s) %s%s%s%s%s\n",
		(what & CE_UPDATED) ? "updated " : "",
		(what & CE_DELETED) ? "deleted " : "",
		(what & CE_LOCKED) ? "locked " : "",
		(what & CE_MASTER_FAILOVER) ? "master-fail " : "",
		(what & CE_SESS_FAILED) ? "sess-fail " : "");
}

static int cld_fuse_getattr(const char *path, struct stat *stbuf)
{
	struct ncld_fh *fh;
	struct ncld_read *nr;
	int error;
	int rc = 0;

	fh = ncld_open(sess, path, COM_READ, &error, 0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				path, error);
		}

		return -EINVAL;
	}

	nr = ncld_get_meta(fh, &error);
	if (!nr) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot get on path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot get on path `%s': %d\n",
				path, error);
		}
		ncld_close(fh);
		return -EINVAL;
	}

	memset(stbuf, 0, sizeof(*stbuf));
	stbuf->st_ino = nr->meta.inum;
	/* FIXME: stbuf->st_mode */
	/* FIXME: stbuf->st_nlink */
	/* FIXME: stbuf->st_size = nr->meta.size; */
	stbuf->st_blksize = 512;
	/* FIXME: stbuf->st_blocks = nr->meta.size / 512; */
	stbuf->st_atime = nr->meta.time_modify;
	stbuf->st_mtime = nr->meta.time_modify;
	stbuf->st_ctime = nr->meta.time_modify;

	ncld_read_free(nr);
	ncld_close(fh);
	return rc;
}

static int cld_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	struct ncld_fh *fh;
	struct ncld_read *nr;
	struct cld_dirent_cur dc;
	const char *data;
	size_t data_len;
	unsigned int n_records;
	int error, i, rc;
	bool first;

	fh = ncld_open(sess, path, COM_DIRECTORY, &error, 0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				path, error);
		}

		return -EINVAL;
	}

	nr = ncld_get(fh, &error);
	if (!nr) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot get on path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot get on path `%s': %d\n",
				path, error);
		}
		ncld_close(fh);
		return -EINVAL;
	}

	data = nr->ptr;
	data_len = nr->length;

	rc = cldc_dirent_count(data, data_len);
	if (rc < 0) {
		fprintf(stderr, TAG ": cldc_dirent_count failed on path `%s'\n",
			path);
		ncld_read_free(nr);
		ncld_close(fh);
		return -EINVAL;
	}
	n_records = rc;

	cldc_dirent_cur_init(&dc, data, data_len);

	first = true;
	for (i = 0; i < n_records; i++) {
		char *s;

		if (first) {
			first = false;

			if (cldc_dirent_first(&dc) < 0)
				break;
		} else {
			if (cldc_dirent_next(&dc) < 0)
				break;
		}

		s = cldc_dirent_name(&dc);

		/* return directory entry name to FUSE */
		filler(buf, s, NULL, 0);

		free(s);
	}

	cldc_dirent_cur_fini(&dc);

	ncld_read_free(nr);
	ncld_close(fh);
	return 0;
}

static int cld_fuse_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	struct ncld_fh *fh;
	struct ncld_read *nr;
	const char *data;
	size_t data_len, copy_len;
	int error;
	int rc = 0;

	fh = ncld_open(sess, path, COM_READ, &error, 0, NULL, NULL);
	if (!fh) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open path `%s': %d\n",
				path, error);
		}

		return -EINVAL;
	}

	nr = ncld_get(fh, &error);
	if (!nr) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot get on path `%s': %s\n",
				path, strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot get on path `%s': %d\n",
				path, error);
		}
		ncld_close(fh);
		return -EINVAL;
	}

	data = nr->ptr;
	data_len = nr->length;

	/* verify offset within file size */
	if (offset > data_len) {
		rc = -EINVAL;
		goto out;
	}

	/* truncate returned data, if requesting more bytes than available */
	if ((data_len - offset) > size)
		copy_len = data_len - offset;
	else
		copy_len = size;

	/* fill FUSE return buffer */
	memcpy(buf, data + offset, copy_len);

out:
	ncld_read_free(nr);
	ncld_close(fh);
	return rc;
}

static void cld_fuse_destroy(void *dummy)
{
	ncld_sess_close(sess);
}

static struct fuse_operations cld_fuse_ops = {
	.getattr	= cld_fuse_getattr,
	.readdir	= cld_fuse_readdir,
	.read		= cld_fuse_read,
	.destroy	= cld_fuse_destroy,
};

static bool push_host(const char *arg)
{
	char *colon;
	unsigned int port;
	struct cldc_host *dr;

	dr = malloc(sizeof(*dr));
	if (!dr) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, sizeof(*dr));
		goto err;
	}
	memset(dr, 0, sizeof(*dr));

	dr->host = strdup(arg);
	if (!dr->host) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, strlen(arg));
		goto err_out;
	}

	colon = strrchr(dr->host, ':');
	if (!colon) {
		fprintf(stderr, "no port in host specifier `%s'\n", dr->host);
		goto err_out_host;
	}

	if (sscanf(colon, ":%u", &port) != 1) {
		fprintf(stderr, "port `%s' is invalid\n", colon+1);
		goto err_out_host;
	}
	if (port < 1 || port > 65535) {
		fprintf(stderr, "port `%s' is out of range\n", colon+1);
		goto err_out_host;
	}

	dr->port = port;

	*colon = 0;

	param.host_list = g_list_append(param.host_list, dr);

	return true;

err_out_host:
	free(dr->host);
err_out:
	free(dr);
err:
	return false;
}

static const struct fuse_opt cldfuse_opts[] = {
	FUSE_OPT_KEY("-h",		0),
	FUSE_OPT_KEY("--host",		0),
	FUSE_OPT_END
};

static int cldfuse_process_arg(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	switch (key) {
	case 0:
		if (!push_host(arg))
			return -1;
		return 0;	/* discard arg */
	default:
		return 1;	/* keep arg */
	}
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct cldc_host *dr;
	int error;

	if (fuse_opt_parse(&args, NULL, cldfuse_opts, cldfuse_process_arg)) {
		fprintf(stderr, "Failed to parse one or more options\n");
		return 1;
	}

	if (!param.host_list) {
		enum { hostsz = 64 };
		char hostb[hostsz];

		if (gethostname(hostb, hostsz-1) < 0) {
			fprintf(stderr, TAG ": gethostname error: %s\n",
				strerror(errno));
			return 1;
		}
		hostb[hostsz-1] = 0;
		if (cldc_getaddr(&param.host_list, hostb, &cldfuse_log)) {
			fprintf(stderr, TAG ": Unable to find a CLD host\n");
			return 1;
		}
	}

	dr = param.host_list->data;

	sess = ncld_sess_open(dr->host, dr->port, &error, sess_event, NULL,
			     "cldfuse", "cldfuse");
	if (!sess) {
		if (error < 1000) {
			fprintf(stderr, TAG ": cannot open CLD session: %s\n",
				strerror(error));
		} else {
			fprintf(stderr, TAG ": cannot open CLD session: %d\n",
				error);
		}
		return 1;
	}

	return fuse_main(args.argc, args.argv, &cld_fuse_ops, NULL);
}


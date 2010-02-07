
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
#include <fuse.h>
#include <errno.h>

static int cld_fuse_getattr(const char *path, struct stat *stbuf)
{
	return -EOPNOTSUPP;
}

static int cld_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	return -EOPNOTSUPP;
}

static int cld_fuse_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	return -EOPNOTSUPP;
}

static struct fuse_operations cld_fuse_ops = {
	.getattr	= cld_fuse_getattr,
	.readdir	= cld_fuse_readdir,
	.read		= cld_fuse_read,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &cld_fuse_ops, NULL);
}


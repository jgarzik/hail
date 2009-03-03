#ifndef __CLDB_H__
#define __CLDB_H__

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


#include <stdbool.h>
#include <db.h>

typedef uint32_t cldino_t;

struct session;

enum {
	INO_ROOT		= 10,
	INO_RESERVED_LAST	= 50,
};

enum inode_flags {
	CIFL_DIR		= (1 << 0),	/* is a directory */
};

struct raw_session {
	uint8_t			clid[8];	/* client id */
	char			addr[64];	/* IP address */
	uint64_t		last_contact;	/* time of last contact */
	uint64_t		next_fh;	/* next fh */
	uint32_t		n_handles;
	/* list of handles */
};

struct raw_handle_key {
	uint8_t			clid[8];	/* client id */
	uint64_t		fh;		/* handle id */
};

struct raw_handle {
	uint8_t			clid[8];	/* client id */
	uint64_t		fh;		/* handle id */
	uint32_t		ino_len;	/* inode name len */
	uint32_t		mode;		/* open mode */
	uint32_t		events;		/* event mask */
	/* inode name */
};

struct raw_inode {
	cldino_t		inum;		/* unique inode number */
	uint32_t		ino_len;	/* inode name len */
	uint32_t		size;		/* data size */
	uint64_t		version;	/* inode version */
	uint64_t		time_create;
	uint64_t		time_modify;
	uint32_t		flags;		/* inode flags; CIFL_xxx */
	/* inode name */
};

struct cldb {
	char		*home;			/* database home dir */
	char		*key;			/* database AES key */

	DB_ENV		*env;			/* db4 env ptr */

	DB		*sessions;		/* client sessions */

	DB		*inodes;		/* inode metadata */
	DB		*inode_names;		/* inode index, by name */

	DB		*data;			/* inode data */

	DB		*handles;		/* open file handles */
	DB		*handle_idx;		/* handles (by inode) */
};


extern int cldb_open(struct cldb *cldb, unsigned int env_flags,
	unsigned int flags, const char *errpfx, bool do_syslog);
extern void cldb_close(struct cldb *cldb);

extern int cldb_session_get(DB_TXN *txn, uint8_t *clid, struct raw_session **sess,
		     bool notfound_err, bool rmw);
extern int cldb_session_put(DB_TXN *txn, struct raw_session *sess, int put_flags);

extern int cldb_inode_get(DB_TXN *txn, cldino_t inum,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags);
extern int cldb_inode_put(DB_TXN *txn, struct raw_inode *inode, int put_flags);
extern int cldb_inode_get_byname(DB_TXN *txn, char *name, size_t name_len,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags);
extern struct raw_inode *cldb_inode_new(DB_TXN *txn, char *name, size_t name_len,
				 uint32_t flags);
extern size_t raw_ino_size(const struct raw_inode *ino);

extern int cldb_data_get(DB_TXN *txn, char *name, size_t name_len,
		  void **data_out, size_t *data_len,
		  bool notfound_err, bool rmw);
extern int cldb_data_put(DB_TXN *txn, char *name, size_t name_len,
		  void *data, size_t data_len, int put_flags);

extern struct raw_handle *cldb_handle_new(struct session *sess,
				   const char *name, size_t name_len,
				   uint32_t mode, uint32_t events);
extern int cldb_handle_put(DB_TXN *txn, struct raw_handle *h, int put_flags);

#endif /* __CLDB_H__ */

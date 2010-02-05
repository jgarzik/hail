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
#include <cld-private.h>
#include <cld_msg_rpc.h>

typedef uint64_t cldino_t;

struct session;

/*
 * session record key:		uint8_t sid[CLD_SID_SZ]
 */

struct raw_session {
	uint8_t			sid[CLD_SID_SZ]; /* session id */
	uint16_t		addr_len;
	char			addr[64];	/* IP address */
	char			user[CLD_MAX_USERNAME];	/* username */
	uint64_t		last_contact;	/* time of last contact */
	uint64_t		next_fh;	/* next fh */
	uint64_t		next_seqid_in;
	uint64_t		next_seqid_out;
};

struct raw_handle_key {
	uint8_t			sid[CLD_SID_SZ]; /* session id */
	uint64_t		fh;		/* handle id */
};

/*
 * handle record key:		struct raw_handle_key
 * handle secondary index key:	cldino_t inum (duplicate keys ok)
 */

struct raw_handle {
	uint8_t			sid[CLD_SID_SZ]; /* session id */
	uint64_t		fh;		/* handle id */
	cldino_t		inum;		/* inode number */
	uint32_t		mode;		/* open mode */
	uint32_t		events;		/* event mask */
};

enum {
	CLD_INO_ROOT		= 10,
	CLD_INO_RESERVED_LAST	= 50,
};

enum inode_flags {
	CIFL_DIR		= (1 << 0),	/* is a directory */
};

/*
 * inode record key:		cldino_t inum
 * inode secondary index key:	inode name
 */

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

enum lock_flags {
	CLFL_SHARED		= (1 << 0),	/* a shared (read) lock */
	CLFL_PENDING		= (1 << 1),	/* lock waiting to be acq. */
};

/*
 * lock record key:		cldino_t inum (duplicate keys ok)
 */

struct raw_lock {
	cldino_t		inum;
	uint8_t			sid[CLD_SID_SZ]; /* session id */
	uint64_t		fh;		/* handle id */
	uint64_t		ctime;
	uint32_t		flags;		/* lock flags: CLFL_xxxx */
};

enum db_event {
	CLDB_EV_NONE, CLDB_EV_CLIENT, CLDB_EV_MASTER, CLDB_EV_ELECTED
};

struct cldb {
	bool		is_master;
	bool		keyed;			/* using encryption? */
	bool		up;			/* databases open? */

	const char	*home;			/* database home dir */
	void		(*state_cb)(enum db_event);

	DB_ENV		*env;			/* db4 env ptr */

	DB		*sessions;		/* client sessions */

	DB		*inodes;		/* inode metadata */
	DB		*inode_names;		/* inode index, by name */

	DB		*data;			/* inode data */

	DB		*handles;		/* open file handles */
	DB		*handle_idx;		/* handles (by inode) */

	DB		*locks;			/* held locks */
};


extern int cldb_init(struct cldb *cldb, const char *db_home, const char *db_password,
	      unsigned int env_flags, const char *errpfx, bool do_syslog,
	      unsigned int flags, void (*cb)(enum db_event));
extern void cldb_down(struct cldb *cldb);
extern void cldb_fini(struct cldb *cldb);

extern int cldb_session_get(DB_TXN *txn, uint8_t *sid, struct raw_session **sess,
		     bool notfound_err, bool rmw);
extern int cldb_session_put(DB_TXN *txn, struct raw_session *sess, int put_flags);
extern int cldb_session_del(DB_TXN *txn, uint8_t *sid);

extern int cldb_inode_get(DB_TXN *txn, cldino_t inum,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags);
extern int cldb_inode_put(DB_TXN *txn, struct raw_inode *inode, int put_flags);
extern int cldb_inode_get_byname(DB_TXN *txn, const char *name, size_t name_len,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags);
extern struct raw_inode *cldb_inode_new(DB_TXN *txn, const char *name, size_t name_len,
				 uint32_t flags);
extern struct raw_inode *cldb_inode_mem(const char *name, size_t name_len,
				 uint32_t flags, cldino_t new_inum);
extern size_t raw_ino_size(const struct raw_inode *ino);

extern int cldb_data_put(DB_TXN *txn, cldino_t inum,
		  const void *data, size_t data_len, int flags);
extern int cldb_data_get(DB_TXN *txn, cldino_t inum,
		  void **data_out, size_t *data_len,
		  bool notfound_err, bool rmw);

extern struct raw_handle *cldb_handle_new(struct session *sess, cldino_t inum,
				   uint32_t mode, uint32_t events);
extern int cldb_handle_put(DB_TXN *txn, struct raw_handle *h, int put_flags);
extern int cldb_handle_del(DB_TXN *txn, uint8_t *sid, uint64_t fh);
extern int cldb_handle_get(DB_TXN *txn, uint8_t *sid, uint64_t fh,
		    struct raw_handle **h_out, int flags);

extern int cldb_lock_del(DB_TXN *txn, uint8_t *sid, uint64_t fh, cldino_t inum);
extern int cldb_lock_add(DB_TXN *txn, uint8_t *sid, uint64_t fh,
			cldino_t inum, bool shared, bool wait, bool *acq);

static inline cldino_t cldino_to_le(cldino_t inum)
{
	return cpu_to_le64(inum);
}

static inline cldino_t cldino_from_le(cldino_t inum)
{
	return le64_to_cpu(inum);
}

#endif /* __CLDB_H__ */

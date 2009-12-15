
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

#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <glib.h>
#include <cld-private.h>
#include "cld.h"

static int cldb_up(struct cldb *cldb, unsigned int flags);

/*
 * db4 page sizes for our various databases.  Filesystem block size
 * is recommended, so 4096 was chosen (default ext3 block size).
 */
enum {
	CLDB_PGSZ_SESSIONS		= 4096,
	CLDB_PGSZ_INODES		= 4096,
	CLDB_PGSZ_INODE_NAMES		= 4096,
	CLDB_PGSZ_DATA			= 4096,
	CLDB_PGSZ_HANDLES		= 4096,
	CLDB_PGSZ_HANDLE_IDX		= 4096,
	CLDB_PGSZ_LOCKS			= 4096,
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	syslog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int inode_name_key(DB *secondary, const DBT *pkey, const DBT *pdata,
			  DBT *key_out)
{
	const struct raw_inode *inode = pdata->data;
	size_t ino_len = pdata->size - sizeof(*inode);
	const void *p;

	if (ino_len != le32_to_cpu(inode->ino_len))
		return -1;

	memset(key_out, 0, sizeof(*key_out));

	/* extract inode pathname out of data following fixed struct */
	p = pdata->data;
	p += sizeof(*inode);

	key_out->data = (void *) p;
	key_out->size = ino_len;

	return 0;
}

static int handle_idx_key(DB *secondary, const DBT *pkey, const DBT *pdata,
			  DBT *key_out)
{
	const struct raw_handle *handle = pdata->data;

	memset(key_out, 0, sizeof(*key_out));

	key_out->data = (void *) &handle->inum;
	key_out->size = sizeof(handle->inum);

	return 0;
}

static int lock_compare(DB *db, const DBT *a_dbt, const DBT *b_dbt)
{
	const struct raw_lock *a = a_dbt->data;
	const struct raw_lock *b = b_dbt->data;
	cldino_t ai = cldino_from_le(a->inum);
	cldino_t bi = cldino_from_le(b->inum);
	uint64_t at = le64_to_cpu(a->ctime);
	uint64_t bt = le64_to_cpu(b->ctime);
	uint64_t afh = le64_to_cpu(a->fh);
	uint64_t bfh = le64_to_cpu(b->fh);
	int64_t v;

	/* compare inode numbers */
	v = ai - bi;
	if (v)
		return v;

	/* compare creation times */
	v = at - bt;
	if (v)
		return v;

	/* compare SIDs */
	v = memcmp(a->sid, b->sid, CLD_SID_SZ);
	if (v)
		return v;

	/* compare file handles */
	return afh - bfh;
}

static int open_db(DB_ENV *env, DB **db_out, const char *name,
		   unsigned int page_size, DBTYPE dbtype, unsigned int flags,
		   int (*bt_compare)(DB *db, const DBT *dbt1, const DBT *dbt2),
		   int (*dup_compare)(DB *db, const DBT *dbt1, const DBT *dbt2),
		   unsigned int fset)
{
	int rc;
	DB *db;
	int retries = 5;

retry:
	rc = db_create(db_out, env, 0);
	if (rc) {
		env->err(env, rc, "db_create");
		return -EIO;
	}

	db = *db_out;

	if (page_size) {
		rc = db->set_pagesize(db, page_size);
		if (rc) {
			db->err(db, rc, "db->set_pagesize");
			goto err_out;
		}
	}

	/* fix everything as little endian */
	rc = db->set_lorder(db, 1234);
	if (rc) {
		db->err(db, rc, "db->set_lorder");
		goto err_out;
	}

	if (bt_compare) {
		rc = db->set_bt_compare(db, bt_compare);
		if (rc) {
			db->err(db, rc, "db->set_bt_compare");
			goto err_out;
		}
	}

	if (fset) {
		rc = db->set_flags(db, fset);
		if (rc) {
			db->err(db, rc, "db->set_flags");
			goto err_out;
		}
	}

	if (dup_compare) {
		rc = db->set_dup_compare(db, dup_compare);
		if (rc) {
			db->err(db, rc, "db->set_dup_compare");
			goto err_out;
		}
	}

	rc = db->open(db, NULL, name, NULL, dbtype,
		      DB_AUTO_COMMIT | flags, S_IRUSR | S_IWUSR);
	if (rc) {
		if (rc == ENOENT || rc == DB_REP_HANDLE_DEAD ||
		    rc == DB_LOCK_DEADLOCK) {
			if (!retries) {
				db->err(db, rc, "db->open retried");
				goto err_out;
			}

			rc = db->close(db, rc == ENOENT ? 0 : DB_NOSYNC);
			if (rc) {
				db->err(db, rc, "db->close");
				goto err_out;
			}

			retries--;
			sleep(2);
			goto retry;
		}

		db->err(db, rc, "db->open");
		goto err_out;
	}

	return 0;

err_out:
	db->close(db, 0);
	return -EIO;
}

static void db4_event(DB_ENV *dbenv, u_int32_t event, void *event_info)
{
	struct cldb *cldb = dbenv->app_private;

	switch (event) {
	case DB_EVENT_REP_CLIENT:
		cldb->is_master = false;
		if (cldb->state_cb)
			(*cldb->state_cb)(CLDB_EV_CLIENT);
		break;
	case DB_EVENT_REP_MASTER:
		cldb->is_master = true;
		if (cldb->state_cb)
			(*cldb->state_cb)(CLDB_EV_MASTER);
		break;
	case DB_EVENT_REP_ELECTED:
		if (cldb->state_cb)
			(*cldb->state_cb)(CLDB_EV_ELECTED);
		break;
	default:
		/* do nothing */
		break;
	}
}

int cldb_init(struct cldb *cldb, const char *db_home, const char *db_password,
	      unsigned int env_flags, const char *errpfx, bool do_syslog,
	      unsigned int flags, void (*cb)(enum db_event))
{
	int rc;
	DB_ENV *dbenv;

	cldb->is_master = true;
	cldb->home = db_home;
	cldb->state_cb = cb;

	rc = db_env_create(&cldb->env, 0);
	if (rc) {
		HAIL_WARN(&srv_log, "cldb->env_create failed: %d", rc);
		return rc;
	}

	dbenv = cldb->env;
	dbenv->app_private = cldb;

	dbenv->set_errpfx(dbenv, errpfx);

	if (do_syslog)
		dbenv->set_errcall(dbenv, db4syslog);
	else
		dbenv->set_errfile(dbenv, stderr);

	/* enable automatic deadlock detection */
	rc = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT);
	if (rc) {
		dbenv->err(dbenv, rc, "set_lk_detect");
		goto err_out;
	}

	/* enable automatic removal of unused logs.  should be re-examined
	 * once this project is more mature, as this makes catastrophic
	 * recovery more difficult.
	 */
	rc = dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
	if (rc) {
		dbenv->err(dbenv, rc, "log_set_config");
		goto err_out;
	}

	if (db_password) {
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_encrypt");
			goto err_out;
		}

		cldb->keyed = true;
	}

	rc = dbenv->set_event_notify(dbenv, db4_event);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->set_event_notify");
		goto err_out;
	}

	/* init DB transactional environment, stored in directory db_home */
	env_flags |= DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL;
	env_flags |= DB_INIT_TXN;
	rc = dbenv->open(dbenv, db_home, env_flags, S_IRUSR | S_IWUSR);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->open");
		goto err_out;
	}

	rc = cldb_up(cldb, flags);
	if (rc)
		goto err_out;

	return 0;

err_out:
	dbenv->close(dbenv, 0);
	return rc;
}

/*
 * open databases
 */
static int cldb_up(struct cldb *cldb, unsigned int flags)
{
	DB_ENV *dbenv = cldb->env;
	int rc;

	if (!cldb->is_master)
		flags &= ~DB_CREATE;
	if (cldb->keyed)
		flags |= DB_ENCRYPT;

	rc = open_db(dbenv, &cldb->sessions, "sessions", CLDB_PGSZ_SESSIONS,
		     DB_HASH, flags, NULL, NULL, 0);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &cldb->inodes, "inodes", CLDB_PGSZ_INODES,
		     DB_HASH, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_sess;

	rc = open_db(dbenv, &cldb->inode_names, "inode_names",
		     CLDB_PGSZ_INODE_NAMES, DB_BTREE, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_ino;

	rc = cldb->inodes->associate(cldb->inodes, NULL,
				     cldb->inode_names, inode_name_key,
				     DB_CREATE);
	if (rc) {
		cldb->inodes->err(cldb->inodes, rc, "inodes->associate");
		goto err_out_ino;
	}

	rc = open_db(dbenv, &cldb->data, "data", CLDB_PGSZ_DATA,
		     DB_HASH, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_ino_name;

	rc = open_db(dbenv, &cldb->handles, "handles", CLDB_PGSZ_HANDLES,
		     DB_BTREE, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_data;

	rc = open_db(dbenv, &cldb->handle_idx, "handle_idx",
		     CLDB_PGSZ_HANDLE_IDX, DB_BTREE, flags, NULL,
		     NULL, DB_DUPSORT);
	if (rc)
		goto err_out_handles;

	rc = cldb->handles->associate(cldb->handles, NULL,
				      cldb->handle_idx, handle_idx_key,
				      DB_CREATE);
	if (rc) {
		cldb->handles->err(cldb->handles, rc, "handles->associate");
		goto err_out_handle_idx;
	}

	rc = open_db(dbenv, &cldb->locks, "locks", CLDB_PGSZ_LOCKS,
		     DB_HASH, flags, NULL, lock_compare, DB_DUPSORT);
	if (rc)
		goto err_out_handle_idx;

	cldb->up = true;

	HAIL_INFO(&srv_log, "databases up");
	return 0;

err_out_handle_idx:
	cldb->handle_idx->close(cldb->handle_idx, 0);
err_out_handles:
	cldb->handles->close(cldb->handles, 0);
err_out_data:
	cldb->data->close(cldb->data, 0);
err_out_ino_name:
	cldb->inode_names->close(cldb->inode_names, 0);
err_out_ino:
	cldb->inodes->close(cldb->inodes, 0);
err_out_sess:
	cldb->sessions->close(cldb->sessions, 0);
err_out:
	return rc;
}

/*
 * close databases
 */
void cldb_down(struct cldb *cldb)
{
	cldb->up = false;

	cldb->locks->close(cldb->locks, 0);
	cldb->handle_idx->close(cldb->handle_idx, 0);
	cldb->handles->close(cldb->handles, 0);
	cldb->data->close(cldb->data, 0);
	cldb->inode_names->close(cldb->inode_names, 0);
	cldb->inodes->close(cldb->inodes, 0);
	cldb->sessions->close(cldb->sessions, 0);

	cldb->locks = NULL;
	cldb->handle_idx = NULL;
	cldb->handles = NULL;
	cldb->data = NULL;
	cldb->inode_names = NULL;
	cldb->inodes = NULL;
	cldb->sessions = NULL;

	HAIL_INFO(&srv_log, "databases down");
}

void cldb_fini(struct cldb *cldb)
{
	cldb->env->close(cldb->env, 0);
	cldb->env = NULL;
}

int cldb_session_del(DB_TXN *txn, uint8_t *sid)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_sess = cld_srv.cldb.sessions;
	DBT key;
	int rc;

	memset(&key, 0, sizeof(key));

	/* key: sid */
	key.data = sid;
	key.size = CLD_SID_SZ;

	rc = db_sess->del(db_sess, txn, &key, 0);
	if (rc)
		dbenv->err(dbenv, rc, "db_sess->del");

	return rc;
}

int cldb_session_get(DB_TXN *txn, uint8_t *sid, struct raw_session **sess_out,
		     bool notfound_err, bool rmw)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_sess = cld_srv.cldb.sessions;
	int rc;
	DBT key, val;
	bool err = false;

	*sess_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: sid */
	key.data = sid;
	key.size = CLD_SID_SZ;

	val.flags = DB_DBT_MALLOC;

	rc = db_sess->get(db_sess, txn, &key, &val, rmw ? DB_RMW : 0);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_sess->get");
		err = true;
	}

	if (!err && (rc == 0))
		*sess_out = val.data;

	return rc;
}

int cldb_session_put(DB_TXN *txn, struct raw_session *sess, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_session = cld_srv.cldb.sessions;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: sid */
	key.data = sess->sid;
	key.size = CLD_SID_SZ;

	val.data = sess;
	val.size = sizeof(*sess);

	rc = db_session->put(db_session, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_session->put");

	return rc;
}

int cldb_inode_get(DB_TXN *txn, cldino_t inum,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode = cld_srv.cldb.inodes;
	int rc;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);

	if (inode_out)
		*inode_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.flags = DB_DBT_MALLOC;

	rc = db_inode->get(db_inode, txn, &key, &val, flags);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_inode->get");
	}

	if (rc == 0) {
		if (inode_out)
			*inode_out = val.data;
		else
			free(val.data);
	}
	return rc;
}

int cldb_inode_get_byname(DB_TXN *txn, const char *name, size_t name_len,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode_names = cld_srv.cldb.inode_names;
	int rc;
	DBT key, val;

	if (inode_out)
		*inode_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode pathname */
	key.data = (char *) name;
	key.size = name_len;

	val.flags = DB_DBT_MALLOC;

	rc = db_inode_names->get(db_inode_names, txn, &key, &val, flags);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_inode_names->get");
	}

	if (rc == 0) {
		if (inode_out)
			*inode_out = val.data;
		else
			free(val.data);
	}
	return rc;
}

size_t raw_ino_size(const struct raw_inode *ino)
{
	size_t sz = sizeof(struct raw_inode);
	uint32_t tmp;

	tmp = le32_to_cpu(ino->ino_len);
	sz += tmp;

	return sz;
}

int cldb_inode_put(DB_TXN *txn, struct raw_inode *inode, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode = cld_srv.cldb.inodes;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inode->inum;
	key.size = sizeof(inode->inum);

	val.data = inode;
	val.size = raw_ino_size(inode);

	rc = db_inode->put(db_inode, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_inode->put");

	return rc;
}

struct raw_inode *cldb_inode_new(DB_TXN *txn, const char *name, size_t name_len,
				 uint32_t flags)
{
	int rc, limit = 100000;
	bool found = false;
	cldino_t new_inum = 0;

	/* allocate a new inode number, by repeatedly choosing a
	 * random number, then verifying that that number is
	 * an unused/unallocated inode number
	 */
	while (limit-- > 0) {
		new_inum = (cldino_t) rand();

		if (new_inum <= CLD_INO_RESERVED_LAST)
			continue;

		rc = cldb_inode_get(txn, new_inum, NULL, false, 0);
		if (rc) {
			if (rc == DB_NOTFOUND)
				found = true;
			break;
		}
	}

	if (!found)
		return NULL;

	return cldb_inode_mem(name, name_len, flags, new_inum);
}

struct raw_inode *cldb_inode_mem(const char *name, size_t name_len,
				 uint32_t flags, cldino_t new_inum)
{
	struct raw_inode *ino;
	void *mem;

	/* build in-memory inode */
	mem = calloc(1, sizeof(*ino) + name_len + CLD_ALIGN8(name_len));
	if (!mem)
		return NULL;

	ino = mem;
	ino->inum = cldino_to_le(new_inum);
	ino->ino_len = cpu_to_le32(name_len);
	ino->time_create =
	ino->time_modify = cpu_to_le64(current_time.tv_sec);
	ino->flags = cpu_to_le32(flags);

	memcpy(mem + sizeof(*ino), name, name_len);

	return ino;
}

int cldb_data_get(DB_TXN *txn, cldino_t inum,
		  void **data_out, size_t *data_len,
		  bool notfound_err, bool rmw)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_data = cld_srv.cldb.data;
	int rc;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);

	*data_out = NULL;
	*data_len = 0;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.flags = DB_DBT_MALLOC;

	rc = db_data->get(db_data, txn, &key, &val, rmw ? DB_RMW : 0);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_data->get");
	}

	if (!rc) {
		*data_out = val.data;
		*data_len = val.size;
	}

	return rc;
}

int cldb_data_put(DB_TXN *txn, cldino_t inum,
		  const void *data, size_t data_len, int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_data = cld_srv.cldb.data;
	int rc;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.data = (void *) data;
	val.size = data_len;

	rc = db_data->put(db_data, txn, &key, &val, flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_data->put");

	return rc;
}

struct raw_handle *cldb_handle_new(struct session *sess, cldino_t inum,
				   uint32_t mode, uint32_t events)
{
	struct raw_handle *h;
	uint64_t fh;
	void *mem;

	mem = calloc(1, sizeof(*h));
	if (!mem)
		return NULL;

	h = mem;
	fh = sess->next_fh;
	sess->next_fh++;

	memcpy(h->sid, sess->sid, sizeof(h->sid));
	h->fh = cpu_to_le64(fh);
	h->inum = cldino_to_le(inum);
	h->mode = cpu_to_le32(mode);
	h->events = cpu_to_le32(events);

	return h;
}

int cldb_handle_get(DB_TXN *txn, uint8_t *sid, uint64_t fh,
		    struct raw_handle **h_out, int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_handle = cld_srv.cldb.handles;
	int rc;
	DBT key, val;
	struct raw_handle_key hkey;

	if (h_out)
		*h_out = NULL;

	memcpy(hkey.sid, sid, CLD_SID_SZ);
	hkey.fh = cpu_to_le64(fh);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: (sid, fh) */
	key.data = &hkey;
	key.size = sizeof(hkey);

	val.flags = DB_DBT_MALLOC;

	rc = db_handle->get(db_handle, txn, &key, &val, flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	if (rc == 0) {
		if (h_out)
			*h_out = val.data;
		else
			free(val.data);
	}

	return rc;
}

int cldb_handle_put(DB_TXN *txn, struct raw_handle *h, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_handle = cld_srv.cldb.handles;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: (sid, fh) */
	key.data = h;
	key.size = sizeof(struct raw_handle_key);

	val.data = h;
	val.size = sizeof(*h);

	rc = db_handle->put(db_handle, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	return rc;
}

int cldb_handle_del(DB_TXN *txn, uint8_t *sid, uint64_t fh)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_handle = cld_srv.cldb.handles;
	int rc;
	DBT key;
	struct raw_handle_key hkey;

	memcpy(hkey.sid, sid, CLD_SID_SZ);
	hkey.fh = cpu_to_le64(fh);

	memset(&key, 0, sizeof(key));

	/* key: (sid, fh) */
	key.data = &hkey;
	key.size = sizeof(hkey);

	rc = db_handle->del(db_handle, txn, &key, 0);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	return rc;
}

int cldb_lock_del(DB_TXN *txn, uint8_t *sid, uint64_t fh, cldino_t inum)
{
	DBC *cur;
	DB *db_locks = cld_srv.cldb.locks;
	int rc;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);
	struct raw_lock lock;
	int gflags;

	rc = db_locks->cursor(db_locks, txn, &cur, 0);
	if (rc) {
		db_locks->err(db_locks, rc, "db_locks->cursor");
		return rc;
	}

	memset(&key, 0, sizeof(key));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.flags = DB_DBT_USERMEM;
	val.data = &lock;
	val.ulen = sizeof(lock);

	/* loop through all locks attached to this inum, searching
	 * for matching lock
	 */
	gflags = DB_SET;
	while (1) {
		rc = cur->get(cur, &key, &val, gflags);
		if (rc) {
			if (rc == DB_NOTFOUND)
				break;

			db_locks->err(db_locks, rc, "db_locks->cursor get");
			goto out;
		}

		gflags = DB_NEXT_DUP;

		/* if we have a matching (sid,fh), delete rec and end loop */
		if (!memcmp(lock.sid, sid, CLD_SID_SZ) &&
		    (fh == le64_to_cpu(lock.fh))) {
			rc = cur->del(cur, 0);
			if (rc) {
				db_locks->err(db_locks, rc, "cursor del");
				goto out;
			}

			break;
		}
	}

out:
	cur->close(cur);
	return rc;
}

static int cldb_lock_find(DB_TXN *txn, cldino_t inum, bool want_shared)
{
	DBC *cur;
	DB *db_locks = cld_srv.cldb.locks;
	int rc, gflags;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);
	struct raw_lock lock;
	uint32_t lflags;

	rc = db_locks->cursor(db_locks, txn, &cur, 0);
	if (rc) {
		db_locks->err(db_locks, rc, "db_locks->cursor");
		return rc;
	}

	memset(&key, 0, sizeof(key));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.flags = DB_DBT_USERMEM;
	val.data = &lock;
	val.ulen = sizeof(lock);

	/* loop through locks associated with this inode, searching
	 * for a conflicting acquired lock
	 */
	gflags = DB_SET;
	while (1) {
		rc = cur->get(cur, &key, &val, gflags);
		if (rc) {
			/* no locks, or no next-dup (rc == DB_NOTFOUND) */
			if (rc == DB_NOTFOUND)
				break;

			db_locks->err(db_locks, rc, "db_locks->cursor get");
			break;
		}

		gflags = DB_NEXT_DUP;

		lflags = le32_to_cpu(lock.flags);

		/* pending locks do not conflict */
		if (lflags & CLFL_PENDING)
			continue;

		/* if conflicting lock found, end loop (rc == 0) */
		if (!want_shared ||
		    (want_shared && (!(lflags & CLFL_SHARED))))
			break;
	}

	cur->close(cur);
	return rc;
}

int cldb_lock_add(DB_TXN *txn, uint8_t *sid, uint64_t fh,
		  cldino_t inum, bool shared, bool wait, bool *acquired)
{
	int rc;
	struct raw_lock lock;
	cldino_t inum_le = cldino_to_le(inum);
	DBT key, val;
	DB *db_locks = cld_srv.cldb.locks;
	bool have_conflict = false;
	uint32_t lock_flags = 0;

	if (acquired)
		*acquired = false;

	/* search for conflicting lock */
	rc = cldb_lock_find(txn, inum, shared);
	if (rc && (rc != DB_NOTFOUND))
		return rc;
	if (rc == 0)
		have_conflict = true;

	/* if trylock failed, exit immediately */
	if (!wait && have_conflict)
		return DB_KEYEXIST;

	/*
	 * build and store new lock record, marked with CLFL_PENDING
	 * if lock was not acquired
	 */

	if (shared)
		lock_flags |= CLFL_SHARED;
	if (wait && have_conflict)
		lock_flags |= CLFL_PENDING;

	lock.inum = cldino_to_le(inum);
	memcpy(lock.sid, sid, sizeof(lock.sid));
	lock.fh = cpu_to_le64(fh);
	lock.ctime = cpu_to_le64(current_time.tv_sec);
	lock.flags = cpu_to_le32(lock_flags);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.data = &lock;
	val.size = sizeof(lock);

	rc = db_locks->put(db_locks, txn, &key, &val, 0);
	if (rc)
		db_locks->err(db_locks, rc, "lock_add db4 put");

	if (acquired && !have_conflict && !rc)
		*acquired = true;

	return rc;
}



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
#include "cld.h"

enum {
	CLDB_PGSZ_SESSIONS		= 4096,
	CLDB_PGSZ_INODES		= 4096,
	CLDB_PGSZ_INODE_NAMES		= 4096,
	CLDB_PGSZ_DATA			= 4096,
	CLDB_PGSZ_HANDLES		= 4096,
	CLDB_PGSZ_HANDLE_IDX		= 4096,
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

	if (ino_len != GUINT32_FROM_LE(inode->ino_len))
		return -1;

	memset(key_out, 0, sizeof(*key_out));

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

static int open_db(DB_ENV *env, DB **db_out, const char *name,
		   unsigned int page_size, DBTYPE dbtype, unsigned int flags,
		   int (*bt_compare)(DB *db, const DBT *dbt1, const DBT *dbt2))
{
	int rc;
	DB *db;

	rc = db_create(db_out, env, 0);
	if (rc) {
		env->err(env, rc, "db_create");
		return -EIO;
	}

	db = *db_out;

	rc = db->set_pagesize(db, page_size);
	if (rc) {
		db->err(db, rc, "db->set_pagesize");
		rc = -EIO;
		goto err_out;
	}

	/* fix everything as little endian */
	rc = db->set_lorder(db, 1234);
	if (rc) {
		db->err(db, rc, "db->set_lorder");
		rc = -EIO;
		goto err_out;
	}

	if (bt_compare) {
		rc = db->set_bt_compare(db, bt_compare);
		if (rc) {
			db->err(db, rc, "db->set_bt_compare");
			rc = -EIO;
			goto err_out;
		}
	}

	rc = db->open(db, NULL, name, NULL, dbtype,
		      DB_AUTO_COMMIT | flags, S_IRUSR | S_IWUSR);
	if (rc) {
		db->err(db, rc, "db->open");
		rc = -EIO;
		goto err_out;
	}

	return 0;

err_out:
	db->close(db, 0);
	return rc;
}

int cldb_open(struct cldb *cldb, unsigned int env_flags, unsigned int flags,
	     const char *errpfx, bool do_syslog)
{
	const char *db_home, *db_password;
	int rc;
	DB_ENV *dbenv;

	/*
	 * open DB environment
	 */

	db_home = cldb->home;
	g_assert(db_home != NULL);

	/* this isn't a very secure way to handle passwords */
	db_password = cldb->key;

	rc = db_env_create(&cldb->env, 0);
	if (rc) {
		fprintf(stderr, "cldb->env_create failed: %d\n", rc);
		return rc;
	}

	dbenv = cldb->env;

	dbenv->set_errpfx(dbenv, errpfx);

	if (do_syslog)
		dbenv->set_errcall(dbenv, db4syslog);
	else
		dbenv->set_errfile(dbenv, stderr);

	if (db_password) {
		flags |= DB_ENCRYPT;
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_encrypt");
			goto err_out;
		}

		memset(cldb->key, 0, strlen(cldb->key));
		free(cldb->key);
		cldb->key = NULL;
	}

	/* init DB transactional environment, stored in directory db_home */
	rc = dbenv->open(dbenv, db_home,
			 env_flags |
			 DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL |
			 DB_INIT_TXN, S_IRUSR | S_IWUSR);
	if (rc) {
		if (dbenv)
			dbenv->err(dbenv, rc, "dbenv->open");
		else
			fprintf(stderr, "dbenv->open failed: %d\n", rc);
		goto err_out;
	}

	/*
	 * Open databases
	 */

	rc = open_db(dbenv, &cldb->sessions, "sessions", CLDB_PGSZ_SESSIONS,
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &cldb->inodes, "inodes", CLDB_PGSZ_INODES,
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out_sess;

	rc = open_db(dbenv, &cldb->inode_names, "inode_names",
		     CLDB_PGSZ_INODE_NAMES, DB_BTREE, flags, NULL);
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
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out_ino_name;

	rc = open_db(dbenv, &cldb->handles, "handles", CLDB_PGSZ_HANDLES,
		     DB_BTREE, flags, NULL);
	if (rc)
		goto err_out_data;

	rc = open_db(dbenv, &cldb->handle_idx, "handle_idx",
		     CLDB_PGSZ_HANDLE_IDX, DB_BTREE, flags | DB_DUP, NULL);
	if (rc)
		goto err_out_handles;

	rc = cldb->handles->associate(cldb->handles, NULL,
				      cldb->handle_idx, handle_idx_key,
				      DB_CREATE);
	if (rc) {
		cldb->handles->err(cldb->handles, rc, "handles->associate");
		goto err_out_handle_idx;
	}

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
	dbenv->close(dbenv, 0);
	return rc;
}

void cldb_close(struct cldb *cldb)
{
	cldb->handle_idx->close(cldb->handle_idx, 0);
	cldb->handles->close(cldb->handles, 0);
	cldb->data->close(cldb->data, 0);
	cldb->inode_names->close(cldb->inodes, 0);
	cldb->inodes->close(cldb->inodes, 0);
	cldb->sessions->close(cldb->sessions, 0);
	cldb->env->close(cldb->env, 0);

	cldb->handle_idx = NULL;
	cldb->handles = NULL;
	cldb->data = NULL;
	cldb->inode_names = NULL;
	cldb->inodes = NULL;
	cldb->sessions = NULL;
	cldb->env = NULL;
}

int cldb_session_get(DB_TXN *txn, uint8_t *clid, struct raw_session **sess_out,
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

	key.data = clid;
	key.size = CLD_ID_SZ;

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

static size_t raw_session_size(const struct raw_session *sess)
{
	size_t sz = sizeof(struct raw_session);

	sz += GUINT32_FROM_LE(sess->n_handles) * sizeof(uint64_t);

	return sz;
}

int cldb_session_put(DB_TXN *txn, struct raw_session *sess, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_session = cld_srv.cldb.sessions;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = sess->clid;
	key.size = sizeof(sess->clid);

	val.data = sess;
	val.size = raw_session_size(sess);

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
	bool err = false;
	cldino_t inum_le = cldino_to_le(inum);

	if (inode_out)
		*inode_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &inum_le;
	key.size = sizeof(inum_le);

	if (inode_out)
		val.flags = DB_DBT_MALLOC;

	rc = db_inode->get(db_inode, txn, &key, &val, flags);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_inode->get");
		err = true;
	}

	if (!err && (rc == 0) && inode_out)
		*inode_out = val.data;
	
	return rc;
}

int cldb_inode_get_byname(DB_TXN *txn, char *name, size_t name_len,
		   struct raw_inode **inode_out, bool notfound_err,
		   int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode_names = cld_srv.cldb.inode_names;
	int rc;
	DBT key, val;
	bool err = false;

	if (inode_out)
		*inode_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = name;
	key.size = name_len;

	if (inode_out)
		val.flags = DB_DBT_MALLOC;

	rc = db_inode_names->get(db_inode_names, txn, &key, &val, flags);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_inode_names->get");
		err = true;
	}

	if (!err && (rc == 0) && inode_out)
		*inode_out = val.data;
	
	return rc;
}

size_t raw_ino_size(const struct raw_inode *ino)
{
	size_t sz = sizeof(struct raw_inode);
	uint32_t tmp;

	tmp = GUINT32_FROM_LE(ino->ino_len);
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

	key.data = &inode->inum;
	key.size = sizeof(inode->inum);

	val.data = inode;
	val.size = raw_ino_size(inode);

	rc = db_inode->put(db_inode, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_inode->put");

	return rc;
}

struct raw_inode *cldb_inode_new(DB_TXN *txn, char *name, size_t name_len,
				 uint32_t flags)
{
	struct raw_inode *ino;
	void *mem;
	int rc, limit = 100000;
	bool found = false;
	cldino_t new_inum = 0;

	while (limit-- > 0) {
		new_inum = (cldino_t) rand();

		if (new_inum <= INO_RESERVED_LAST)
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

	ino = calloc(1, sizeof(*ino) + name_len + ALIGN8(name_len));
	if (!ino)
		return NULL;
	
	ino->inum = cldino_to_le(new_inum);
	ino->ino_len = GUINT32_TO_LE(name_len);
	ino->time_create = 
	ino->time_modify = GUINT64_TO_LE(current_time);
	ino->flags = GUINT32_TO_LE(flags);

	mem = ino + sizeof(*ino);
	memcpy(mem, name, name_len);

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
	bool err = false;
	cldino_t inum_le = cldino_to_le(inum);

	*data_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.flags = DB_DBT_MALLOC;

	rc = db_data->get(db_data, txn, &key, &val, rmw ? DB_RMW : 0);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_data->get");
		err = true;
	}

	if (!err) {
		*data_out = val.data;
		*data_len = val.size;
	}
	
	return rc;
}

int cldb_data_put(DB_TXN *txn, cldino_t inum,
		  void *data, size_t data_len, int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_data = cld_srv.cldb.data;
	int rc;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.data = data;
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

	memcpy(h->clid, sess->clid, sizeof(h->clid));
	h->fh = GUINT64_TO_LE(fh);
	h->inum = cldino_to_le(inum);
	h->mode = GUINT32_TO_LE(mode);
	h->events = GUINT32_TO_LE(events);

	return h;
}

int cldb_handle_get(DB_TXN *txn, uint8_t *clid, uint64_t fh,
		    struct raw_handle **h_out, int flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_handle = cld_srv.cldb.handles;
	int rc;
	DBT key, val;
	struct raw_handle_key hkey;

	if (h_out)
		*h_out = NULL;

	memcpy(&hkey.clid, &clid, CLD_ID_SZ);
	hkey.fh = GUINT64_TO_LE(fh);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &hkey;
	key.size = sizeof(hkey);

	if (h_out)
		val.flags = DB_DBT_MALLOC;

	rc = db_handle->get(db_handle, txn, &key, &val, flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	if ((rc == 0) && h_out)
		*h_out = val.data;

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

	key.data = h;
	key.size = sizeof(struct raw_handle_key);

	val.data = h;
	val.size = sizeof(*h);

	rc = db_handle->put(db_handle, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	return rc;
}

int cldb_handle_del(DB_TXN *txn, uint8_t *clid, uint64_t fh)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_handle = cld_srv.cldb.handles;
	int rc;
	DBT key;
	struct raw_handle_key hkey;

	memcpy(&hkey.clid, &clid, CLD_ID_SZ);
	hkey.fh = GUINT64_TO_LE(fh);

	memset(&key, 0, sizeof(key));

	key.data = &hkey;
	key.size = sizeof(hkey);

	rc = db_handle->del(db_handle, txn, &key, 0);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	return rc;
}


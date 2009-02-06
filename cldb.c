
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
	CLDB_PGSZ_SESSIONS		= 1024,
	CLDB_PGSZ_INODES		= 1024,
	CLDB_PGSZ_DATA			= 1024,
	CLDB_PGSZ_HANDLES		= 1024,
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	syslog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int open_db(DB_ENV *env, DB **db_out, const char *name,
		   unsigned int page_size, unsigned int flags)
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

	rc = db->open(db, NULL, name, NULL, DB_HASH,
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

	rc = open_db(dbenv, &cldb->sessions, "sessions", CLDB_PGSZ_SESSIONS, flags);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &cldb->inodes, "inodes", CLDB_PGSZ_INODES, flags);
	if (rc)
		goto err_out_sess;

	rc = open_db(dbenv, &cldb->data, "data", CLDB_PGSZ_DATA, flags);
	if (rc)
		goto err_out_ino;

	rc = open_db(dbenv, &cldb->handles, "handles", CLDB_PGSZ_HANDLES,flags);
	if (rc)
		goto err_out_ino;

	return 0;

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
	cldb->sessions->close(cldb->sessions, 0);
	cldb->inodes->close(cldb->inodes, 0);
	cldb->data->close(cldb->data, 0);
	cldb->env->close(cldb->env, 0);

	cldb->env = NULL;
	cldb->sessions = NULL;
	cldb->inodes = NULL;
	cldb->data = NULL;
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

	if (!err)
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

int cldb_inode_get(DB_TXN *txn, char *name, size_t name_len,
		   struct raw_inode **inode_out, bool notfound_err, bool rmw)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode = cld_srv.cldb.inodes;
	int rc;
	DBT key, val;
	bool err = false;

	*inode_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = name;
	key.size = name_len;

	val.flags = DB_DBT_MALLOC;

	rc = db_inode->get(db_inode, txn, &key, &val, rmw ? DB_RMW : 0);
	if (rc && ((rc != DB_NOTFOUND) || notfound_err)) {
		dbenv->err(dbenv, rc, "db_inode->get");
		err = true;
	}

	if (!err)
		*inode_out = val.data;
	
	return rc;
}

size_t raw_ino_size(const struct raw_inode *ino)
{
	size_t sz = sizeof(struct raw_inode);
	uint32_t tmp;

	tmp = GUINT32_FROM_LE(ino->ino_len);
	sz += tmp + ALIGN8(tmp);

	sz += GUINT32_FROM_LE(ino->n_handles) * sizeof(struct raw_handle_key);

	return sz;
}

int cldb_inode_put(DB_TXN *txn, char *name, size_t name_len,
		   struct raw_inode *inode, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_inode = cld_srv.cldb.inodes;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = name;
	key.size = name_len;

	val.data = inode;
	val.size = raw_ino_size(inode);

	rc = db_inode->put(db_inode, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_inode->put");

	return rc;
}

struct raw_inode *cldb_inode_new(char *name, size_t name_len, uint32_t flags)
{
	struct raw_inode *ino;
	void *mem;

	ino = calloc(1, sizeof(*ino) + name_len + ALIGN8(name_len));
	if (!ino)
		return NULL;
	
	ino->ino_len = GUINT32_TO_LE(name_len);
	ino->time_create = 
	ino->time_modify = GUINT64_TO_LE(time(NULL));
	ino->flags = GUINT32_TO_LE(flags);

	mem = ino + sizeof(*ino);
	memcpy(mem, name, name_len);

	return ino;
}

int cldb_data_get(DB_TXN *txn, char *name, size_t name_len,
		  void **data_out, size_t *data_len,
		  bool notfound_err, bool rmw)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_data = cld_srv.cldb.data;
	int rc;
	DBT key, val;
	bool err = false;

	*data_out = NULL;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = name;
	key.size = name_len;

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

int cldb_data_put(DB_TXN *txn, char *name, size_t name_len,
		  void *data, size_t data_len, int put_flags)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB *db_data = cld_srv.cldb.data;
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = name;
	key.size = name_len;

	val.data = data;
	val.size = data_len;

	rc = db_data->put(db_data, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_data->put");

	return rc;
}

struct raw_handle *cldb_handle_new(struct raw_session *sess,
				   const char *name, size_t name_len,
				   uint32_t mode, uint32_t events)
{
	struct raw_handle *h;
	uint64_t hid;
	void *mem;

	mem = calloc(1, sizeof(*h) + name_len + ALIGN8(name_len));
	if (!mem)
		return NULL;

	h = mem;
	hid = GUINT64_FROM_LE(sess->next_fh);
	sess->next_fh = GUINT64_TO_LE(hid + 1);

	memcpy(h->clid, sess->clid, sizeof(h->clid));
	h->hid = GUINT64_TO_LE(hid);
	h->ino_len = GUINT32_TO_LE(name_len);
	h->mode = GUINT32_TO_LE(mode);
	h->events = GUINT32_TO_LE(events);

	memcpy(mem + sizeof(*h), name, name_len);

	return h;
}

static size_t raw_handle_size(const struct raw_handle *h)
{
	size_t sz = sizeof(struct raw_handle);
	uint32_t tmp;

	tmp = GUINT32_FROM_LE(h->ino_len);
	sz += tmp + ALIGN8(tmp);

	return sz;
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
	val.size = raw_handle_size(h);

	rc = db_handle->put(db_handle, txn, &key, &val, put_flags);
	if (rc)
		dbenv->err(dbenv, rc, "db_handle->put");

	return rc;
}


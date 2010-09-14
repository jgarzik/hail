
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
#include "hail-config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/sha.h>
#include <cld-private.h>
#include <cld_common.h>
#include <cld_msg_rpc.h>
#include "cld.h"

enum {
	CLD_MAX_UDP_SEG		= 1024,
};

struct pathname_info {
	const char	*dir;
	size_t		dir_len;
	const char	*base;
	size_t		base_len;
};

static bool valid_inode_name(const char *name, size_t name_len)
{
	if (!name || !*name || !name_len)
		return false;
	if (strnlen(name, name_len) != name_len)
		return false;
	if (name[0] != '/')
		return false;
	if (name_len > 1 && name[name_len - 1] == '/')
		return false;
	if (memmem(name, name_len, "//", 2))
		return false;
	return true;
}

static void pathname_parse(const char *path, size_t path_len,
			   struct pathname_info *pinfo)
{
	char *lsl;
	int ofs;

	lsl = memrchr(path, '/', path_len);
	if (!lsl) {	/* We check user paths to start with a slash, but... */
		pinfo->dir = path;
		pinfo->dir_len = 0;
		pinfo->base = path;
		pinfo->base_len = path_len;
		return;
	}
	if (lsl == path) {	/* Special-case root. */
		pinfo->dir = path;
		pinfo->dir_len = 1;
		if (path_len == 1) {
			pinfo->base = path;
			pinfo->base_len = 1;
		} else {
			pinfo->base = path + 1;
			pinfo->base_len = path_len - 1;
		}
		return;
	}
	ofs = lsl - path + 1;

	pinfo->dir = path;
	pinfo->dir_len = ofs - 1;
	pinfo->base = path + ofs;
	pinfo->base_len = path_len - ofs;
}

static int dirent_find(const void *data, size_t data_len,
		       const char *name, size_t name_len,
		       int *ofs_out, size_t *ent_len_out)
{
	const void *p = data;
	size_t tmp_len = data_len;
	size_t str_len, rec_len, pad, total_len;
	const uint16_t *tmp16;
	long ofs;

	while (tmp_len > 0) {
		if (tmp_len < 2)
			return -2;

		tmp16		= p;
		str_len		= le16_to_cpu(*tmp16);
		rec_len		= str_len + 2;
		pad		= CLD_ALIGN8(rec_len);
		total_len	= rec_len + pad;

		if (total_len > tmp_len)
			return -2;

		if ((name_len == str_len) &&
		    !memcmp(p + 2, name, name_len))
			break;

		p += total_len;
		tmp_len -= total_len;
	}

	if (!tmp_len)
		return -1;

	ofs = (p - data);

	if (ofs_out)
		*ofs_out = (int) ofs;
	if (ent_len_out)
		*ent_len_out = total_len;

	return 0;
}

static bool dirdata_delete(void *data, size_t *data_len_io,
			   const char *name, size_t name_len)
{
	int rc, ofs = -1;
	size_t ent_len = 0, new_len;
	size_t data_len = *data_len_io;

	rc = dirent_find(data, data_len, name, name_len, &ofs, &ent_len);
	if (rc)
		return false;

	new_len = data_len - ent_len;

	if ((ofs + ent_len) < data_len)
		memmove(data + ofs,
			data + ofs + ent_len,
			data_len - (ofs + ent_len));

	*data_len_io = new_len;
	return true;
}

static bool dirdata_append(void **data, size_t *data_len,
			   const char *name, size_t name_len)
{
	size_t rec_alloc, new_len, pad, orig_len, rec_len;
	void *mem, *p;
	uint16_t *raw_len;

	rec_len		= name_len + 2;
	pad		= CLD_ALIGN8(rec_len);
	rec_alloc	= rec_len + pad;
	orig_len	= *data_len;
	new_len		= orig_len + rec_alloc;

	mem = realloc(*data, new_len);
	if (!mem) {
		HAIL_CRIT(&srv_log, "%s: out of memory for data [%zu]",
			  __func__, new_len);
		return false;
	}

	/* store 16-bit string length, little endian */
	p = mem + orig_len;
	raw_len = p;
	*raw_len = cpu_to_le16(name_len);
	p += sizeof(uint16_t);

	/* store name, zero pad area (if any) */
	memcpy(p, name, name_len);
	if (pad)
		memset(p + name_len, 0, pad);

	*data = mem;
	*data_len = new_len;
	return true;
}

static int inode_notify(DB_TXN *txn, cldino_t inum, bool deleted)
{
	int rc;
	DB *hand_idx = cld_srv.cldb.handle_idx;
	DBC *cur;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);
	int gflags;
	struct session *sess;
	struct raw_handle h;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.data = &h;
	val.ulen = sizeof(h);
	val.flags = DB_DBT_USERMEM;

	rc = hand_idx->cursor(hand_idx, txn, &cur, 0);
	if (rc) {
		hand_idx->err(hand_idx, rc, "inode_notify cursor");
		return rc;
	}

	gflags = DB_SET;
	while (1) {
		struct cld_msg_event me;

		rc = cur->get(cur, &key, &val, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				hand_idx->err(hand_idx, rc,
					"inode_notify cursor get");
			break;
		}

		gflags = DB_NEXT_DUP;

		if (!deleted && !(le32_to_cpu(h.events) & CE_UPDATED))
			continue;

		sess = g_hash_table_lookup(cld_srv.sessions, h.sid);
		if (!sess) {
			HAIL_WARN(&srv_log, "%s BUG", __func__);
			continue;
		}

		if (!sess->sock_fd) {		/* Freshly recovered session */
			HAIL_DEBUG(&srv_log, "Lost notify sid " SIDFMT
				   " ino %lld", SIDARG(sess->sid),
				   (long long) inum);
			continue;
		}

		memset(&me, 0, sizeof(me));
		me.fh = le64_to_cpu(h.fh);
		me.events = deleted ? CE_DELETED : CE_UPDATED;

		if (!sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_event,
				  (void *)&me, CMO_EVENT, NULL, NULL))
			break;
	}

	rc = cur->close(cur);
	if (rc)
		hand_idx->err(hand_idx, rc, "inode_notify cursor close");

	return 0;
}

static int inode_touch(DB_TXN *txn, struct raw_inode *ino)
{
	int rc;

	ino->time_modify = cpu_to_le64(current_time.tv_sec);
	if (!ino->time_create)
		ino->time_create = ino->time_modify;
	ino->version = cpu_to_le32(le32_to_cpu(ino->version) + 1);

	/* write parent inode */
	rc = cldb_inode_put(txn, ino, 0);
	if (rc)
		return rc;

	rc = inode_notify(txn, cldino_from_le(ino->inum), false);
	if (rc)
		return rc;

	return 0;
}

int inode_lock_rescan(DB_TXN *txn, cldino_t inum)
{
	DBC *cur;
	DB *db_locks = cld_srv.cldb.locks;
	int rc, gflags, acq = 0;
	DBT key, val;
	cldino_t inum_le = cldino_to_le(inum);
	struct raw_lock lock;
	uint32_t lflags;
	struct session *sess;

	rc = db_locks->cursor(db_locks, txn, &cur, 0);
	if (rc) {
		db_locks->err(db_locks, rc, "db_locks->cursor");
		return rc;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	val.data = &lock;
	val.ulen = sizeof(lock);
	val.flags = DB_DBT_USERMEM;

	/* loop through locks associated with this inode, searching
	 * for pending locks that can be converted into acquired
	 */
	gflags = DB_SET | DB_RMW;
	while (1) {
		struct cld_msg_event me;

		rc = cur->get(cur, &key, &val, gflags);
		if (rc) {
			/* no locks, or no next-dup */
			if (rc == DB_NOTFOUND) {
				rc = 0;
				break;
			}

			db_locks->err(db_locks, rc, "db_locks->cursor get");
			break;
		}

		gflags = DB_NEXT_DUP | DB_RMW;

		lflags = le32_to_cpu(lock.flags);

		/* pending locks should be first in the list; if
		 * no more pending locks are present, end scan
		 */
		if (!(lflags & CLFL_PENDING))
			break;

		/* excl lock follows shared lock; do not acquire; end loop */
		if (acq && (!(lflags & CLFL_SHARED)))
			break;

		/* pending lock found; acquire lock */
		lflags &= ~CLFL_PENDING;

		/* update current lock rec at cursor */
		rc = cur->put(cur, NULL, &val, DB_CURRENT);
		if (rc) {
			db_locks->err(db_locks, rc, "db_locks->cursor get");
			break;
		}

		acq++;

		sess = g_hash_table_lookup(cld_srv.sessions, lock.sid);
		if (!sess) {
			HAIL_WARN(&srv_log, "%s BUG", __func__);
			break;
		}

		/*
		 * send lock acquisition notification to new lock holder
		 */

		if (!sess->sock_fd) {		/* Freshly recovered session */
			HAIL_DEBUG(&srv_log, "Lost success sid " SIDFMT
				   " ino %lld", SIDARG(sess->sid),
				   (long long) inum);
			continue;
		}

		memset(&me, 0, sizeof(me));
		me.fh = le64_to_cpu(lock.fh);
		me.events = CE_LOCKED;

		if (!sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_event,
				(void *)&me, CMO_EVENT, NULL, NULL))
			break;
	}

	cur->close(cur);
	return rc;
}

void msg_get(struct session *sess, const void *v)
{
	const struct cld_msg_get *get = v;
	struct cld_msg_get_resp resp;
	struct raw_handle *h = NULL;
	struct raw_inode *inode = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	cldino_t inum;
	uint32_t name_len, inode_size;
	uint32_t omode;
	int rc;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	void *data_mem;
	char *inode_name;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, get->fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = le32_to_cpu(h->mode);

	if (!(omode & COM_READ)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* read inode from db */
	rc = cldb_inode_get(txn, inum, &inode, false, 0);
	if (rc) {
		resp_rc = CLE_INODE_INVAL;
		goto err_out;
	}

	inode_size = le32_to_cpu(inode->size);
	HAIL_DEBUG(&srv_log, "GET-DEBUG: inode->size %u\n", inode_size);

	/* return response containing inode metadata */
	memset(&resp, 0, sizeof(resp));
	resp.msg.code = CLE_OK;
	resp.msg.xid_in = sess->msg_xid;
	resp.inum = le64_to_cpu(inode->inum);
	resp.vers = le64_to_cpu(inode->version);
	resp.time_create = le64_to_cpu(inode->time_create);
	resp.time_modify = le64_to_cpu(inode->time_modify);
	resp.flags = le32_to_cpu(inode->flags);

	name_len = le32_to_cpu(inode->ino_len);
	inode_name = alloca(name_len + 1);
	memcpy (inode_name, inode + 1, name_len);
	inode_name[name_len] = 0;
	resp.inode_name = inode_name;

	resp.data.data_len = 0;
	resp.data.data_val = NULL;

	/* send data, if requested */
	data_mem = NULL;
	if (sess->msg_op == CMO_GET) {
		size_t data_mem_len;

		rc = cldb_data_get(txn, inum, &data_mem, &data_mem_len,
				   false, false);

		/* treat not-found as zero length file, as we may
		 * not yet have created the data record
		 */
		if (rc != DB_NOTFOUND) {
			if (rc || (data_mem_len != inode_size)) {
				if (!rc)
					free(data_mem);
				resp_rc = CLE_DB_ERR;
				goto err_out;
			} else {
				resp.data.data_len = data_mem_len;
				resp.data.data_val = data_mem;
			}
		}
	}

	sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_get_resp,
		     (void *)&resp, CMO_GET, NULL, NULL);
	if (data_mem)
		free(data_mem);

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get read-only txn commit");

	free(h);
	free(inode);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(h);
	free(inode);
}

void msg_open(struct session *sess, const void *v)
{
	const struct cld_msg_open *open = v;
	struct cld_msg_open_resp resp;
	const char *name;
	struct raw_session *raw_sess = NULL;
	struct raw_inode *inode = NULL, *parent = NULL;
	struct raw_handle *h = NULL;
	int rc, name_len;
	bool create, excl, do_dir;
	struct pathname_info pinfo;
	void *parent_data = NULL;
	size_t parent_len;
	uint64_t fh;
	cldino_t inum;
	enum cle_err_codes resp_rc = CLE_OK;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	name = open->inode_name;
	name_len = strlen(name);

	create = open->mode & COM_CREATE;
	excl = open->mode & COM_EXCL;
	do_dir = open->mode & COM_DIRECTORY;

	if (!valid_inode_name(name, name_len) || (create && name_len < 2)) {
		resp_rc = CLE_NAME_INVAL;
		goto err_out;
	}

	pathname_parse(name, name_len, &pinfo);

	/* read inode from db, if it exists */
	rc = cldb_inode_get_byname(txn, name, name_len, &inode, false, DB_RMW);
	if (rc && (rc != DB_NOTFOUND)) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}
	if (!create && (rc == DB_NOTFOUND)) {
		resp_rc = CLE_NAME_INVAL;
		goto err_out;
	}
	if (create && rc == 0) {
		if (excl) {
			resp_rc = CLE_INODE_EXISTS;
			goto err_out;
		} else
			create = false;
	}

	/* if inode exists, make sure COM_DIRECTORY (or lack thereof)
	 * matches the inode's state
	 */
	if (!create) {
		bool have_dir = le32_to_cpu(inode->flags) & CIFL_DIR;

		if (do_dir != have_dir) {
			resp_rc = CLE_MODE_INVAL;
			goto err_out;
		}
	}

	if (create) {
		/* create new in-memory inode */
		inode = cldb_inode_new(txn, name, name_len, 0);
		if (!inode) {
			HAIL_CRIT(&srv_log, "cannot allocate new inode");
			resp_rc = CLE_OOM;
			goto err_out;
		}

		if (do_dir)
			inode->flags = cpu_to_le32(
				le32_to_cpu(inode->flags) | CIFL_DIR);

		/* read parent, to which we will add new child inode */
		rc = cldb_inode_get_byname(txn, pinfo.dir, pinfo.dir_len,
				    &parent, true, 0);
		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}

		/* read parent inode data, if any */
		rc = cldb_data_get(txn, cldino_from_le(parent->inum),
				   &parent_data, &parent_len, false, true);
		if (rc == DB_NOTFOUND) {
			parent_data = NULL;
			parent_len = 0;
		} else if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}

		/* append new record to inode's directory data */
		if (!dirdata_append(&parent_data, &parent_len,
				    pinfo.base, pinfo.base_len)) {
			resp_rc = CLE_OOM;
			goto err_out;
		}

		/* write parent inode's updated directory data */
		rc = cldb_data_put(txn, cldino_from_le(parent->inum),
				   parent_data, parent_len, 0);
		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}

		parent->size = cpu_to_le32(parent_len);

		rc = inode_touch(txn, parent);
		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}
	}

	inum = cldino_from_le(inode->inum);

	/* alloc & init new handle; updates session's next_fh */
	h = cldb_handle_new(sess, inum, open->mode, open->events);
	if (!h) {
		HAIL_CRIT(&srv_log, "cannot allocate handle");
		resp_rc = CLE_OOM;
		goto err_out;
	}

	fh = le64_to_cpu(h->fh);

	/* write newly created file handle */
	rc = cldb_handle_put(txn, h, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	if (create) {
		/* write inode */
		rc = inode_touch(txn, inode);

		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}
	}

	/* encode in-memory session to raw database session struct */
	raw_sess = session_new_raw(sess);

	if (!raw_sess) {
		HAIL_CRIT(&srv_log, "cannot allocate session");
		resp_rc = CLE_OOM;
		goto err_out;
	}

	/* write session */
	rc = cldb_session_put(txn, raw_sess, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "msg_open txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	free(parent_data);
	free(parent);
	free(inode);
	free(raw_sess);
	free(h);

	memset(&resp, 0, sizeof(resp));
	resp.msg.xid_in = sess->msg_xid;
	resp.msg.code = CLE_OK;
	resp.fh = fh;
	sess_sendmsg(sess, (xdrproc_t)xdr_cld_msg_open_resp,
		     (void *)&resp, CMO_OPEN, NULL, NULL);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_open txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(parent_data);
	free(parent);
	free(inode);
	free(raw_sess);
	free(h);
}

void msg_put(struct session *sess, const void *v)
{
	const struct cld_msg_put *put = v;
	struct raw_handle *h = NULL;
	struct raw_inode *inode = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	int rc;
	cldino_t inum;
	uint32_t omode;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, put->fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = le32_to_cpu(h->mode);

	if ((!(omode & COM_WRITE)) ||
	    (omode & COM_DIRECTORY)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* read inode from db */
	rc = cldb_inode_get(txn, inum, &inode, false, DB_RMW);
	if (rc) {
		resp_rc = CLE_INODE_INVAL;
		goto err_out;
	}

	/* store contig. data area in db */
	rc = cldb_data_put(txn, inum,
			   put->data.data_val, put->data.data_len, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	inode->size = cpu_to_le32(put->data.data_len);

	/* update inode */
	rc = inode_touch(txn, inode);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "try_commit_data txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	sess_sendresp_generic(sess, CLE_OK);

	free(h);
	free(inode);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_put txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);

	free(h);
	free(inode);
}

void msg_close(struct session *sess, const void *v)
{
	const struct cld_msg_close *close_msg = v;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	struct raw_handle *h = NULL;
	cldino_t lock_inum = 0;
	bool waiter = false;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, close_msg->fh, &h, DB_RMW);
	if (rc) {
		if (rc == DB_NOTFOUND)
			resp_rc = CLE_FH_INVAL;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	if (le32_to_cpu(h->mode) & COM_LOCK)
		lock_inum = cldino_from_le(h->inum);

	/* delete handle from db */
	rc = cldb_handle_del(txn, sess->sid, close_msg->fh);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* remove locks, if any */
	rc = session_remove_locks(txn, sess->sid,
				  close_msg->fh, lock_inum, &waiter);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* rescan lock_inum if 'waiter', possibly acquiring locks */
	if (waiter) {
		rc = inode_lock_rescan(txn, lock_inum);
		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "msg_close txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	sess_sendresp_generic(sess, CLE_OK);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_close txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(h);
}

void msg_del(struct session *sess, const void *v)
{
	const struct cld_msg_del *del = v;
	enum cle_err_codes resp_rc = CLE_OK;
	int rc, name_len;
	struct pathname_info pinfo;
	struct raw_inode *parent = NULL, *ino = NULL;
	void *parent_data = NULL;
	size_t parent_len;
	cldino_t del_inum;
	DB *inodes = cld_srv.cldb.inodes;
	DB *db_data = cld_srv.cldb.data;
	DB *handle_idx = cld_srv.cldb.handle_idx;
	DBT key;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	name_len = strlen(del->inode_name);
	if (!valid_inode_name(del->inode_name, name_len) || (name_len < 2)) {
		resp_rc = CLE_NAME_INVAL;
		goto err_out_noabort;
	}

	pathname_parse(del->inode_name, name_len, &pinfo);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read parent, to be modified */
	rc = cldb_inode_get_byname(txn, pinfo.dir, pinfo.dir_len,
			    &parent, true, DB_RMW);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* read parent inode data */
	rc = cldb_data_get(txn, cldino_from_le(parent->inum),
			   &parent_data, &parent_len, true, true);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* read inode to be deleted */
	rc = cldb_inode_get_byname(txn, del->inode_name, name_len,
				   &ino, false, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			resp_rc = CLE_NAME_INVAL;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* prevent deletion of non-empty dirs */
	if (le32_to_cpu(ino->flags) & CIFL_DIR) {
		DBT val;

		memset(&key, 0, sizeof(key));
		memset(&val, 0, sizeof(val));

		/* key: inode number */
		key.data = &ino->inum;
		key.size = sizeof(ino->inum);

		val.flags = DB_DBT_MALLOC;

		rc = db_data->get(db_data, txn, &key, &val, 0);
		free(val.data);
		if (rc && (rc != DB_NOTFOUND)) {
			db_data->err(db_data, rc, "db_data->get for rmdir");
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}
		if (rc == 0 && val.size > 0) {
			resp_rc = CLE_DIR_NOTEMPTY;
			goto err_out;
		}
	}

	del_inum = cldino_from_le(ino->inum);

	/* notify interested parties of impending deletion */
	rc = inode_notify(txn, del_inum, true);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	memset(&key, 0, sizeof(key));

	key.data = &ino->inum;
	key.size = sizeof(ino->inum);

	/* delete inode */
	rc = inodes->del(inodes, txn, &key, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			resp_rc = CLE_INODE_INVAL;
		else {
			inodes->err(inodes, rc, "inodes->del");
			resp_rc = CLE_DB_ERR;
		}
		goto err_out;
	}

	/* delete data associated with inode, if any */
	rc = db_data->del(db_data, txn, &key, 0);
	if (rc && (rc != DB_NOTFOUND)) {
		db_data->err(db_data, rc, "db_data->del");
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* delete all filehandles associated with this inode, if any */
	rc = handle_idx->del(handle_idx, txn, &key, 0);
	if (rc && (rc != DB_NOTFOUND)) {
		handle_idx->err(handle_idx, rc, "handle_idx->del");
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* remove record from inode's directory data */
	if (!dirdata_delete(parent_data, &parent_len,
			    pinfo.base, pinfo.base_len)) {
		HAIL_WARN(&srv_log, "dirent del failed");
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* write parent inode's updated directory data */
	rc = cldb_data_put(txn, cldino_from_le(parent->inum),
			   parent_data, parent_len, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	parent->size = cpu_to_le32(parent_len);

	/* update parent dir inode */
	rc = inode_touch(txn, parent);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "msg_del txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	sess_sendresp_generic(sess, CLE_OK);
	free(ino);
	free(parent);
	free(parent_data);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_del txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(ino);
	free(parent);
	free(parent_data);
}

void msg_unlock(struct session *sess, const void *v)
{
	const struct cld_msg_unlock *unlock = v;
	struct raw_handle *h = NULL;
	cldino_t inum;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	uint32_t omode;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, unlock->fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = le32_to_cpu(h->mode);

	if (!(omode & COM_LOCK)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* attempt to given lock on filehandle */
	rc = cldb_lock_del(txn, sess->sid, unlock->fh, inum);
	if (rc) {
		resp_rc = CLE_LOCK_INVAL;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "msg_unlock txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	sess_sendresp_generic(sess, CLE_OK);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_unlock txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(h);
}

void msg_lock(struct session *sess, const void *v)
{
	const struct cld_msg_lock *lock = v;
	bool wait = (sess->msg_op == CMO_LOCK);
	struct raw_handle *h = NULL;
	cldino_t inum;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	uint32_t omode;
	bool acquired = false;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, lock->fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = le32_to_cpu(h->mode);

	if (!(omode & COM_LOCK)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* attempt to add lock */
	rc = cldb_lock_add(txn, sess->sid, lock->fh, inum,
			   lock->flags & CLF_SHARED, wait, &acquired);
	if (rc) {
		if (rc == DB_KEYEXIST)
			resp_rc = CLE_LOCK_CONFLICT;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "msg_lock txn commit");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* lock was added, in the waiting-to-be-acquired state */
	if (!acquired) {
		resp_rc = CLE_LOCK_PENDING;
		goto err_out_noabort;
	}

	/* lock was acquired immediately */
	sess_sendresp_generic(sess, CLE_OK);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_lock txn abort");
err_out_noabort:
	sess_sendresp_generic(sess, resp_rc);
	free(h);
}


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

#include "cld-config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/sha.h>
#include "cld.h"

enum {
	CLD_MAX_UDP_SEG		= 1024,
};

struct pathname_info {
	char		*dir;
	size_t		dir_len;
	char		*base;
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

static void pathname_parse(char *path, size_t path_len,
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
		str_len		= GUINT16_FROM_LE(*tmp16);
		rec_len		= str_len + 2;
		pad		= ALIGN8(rec_len);
		total_len	= rec_len + pad;

		p += 2;
		tmp_len -= 2;

		if (total_len > tmp_len)
			return -2;

		if ((name_len == str_len) &&
		    !memcmp(p, name, name_len))
			break;

		p += total_len;
		tmp_len -= total_len;
	}

	if (!tmp_len)
		return -1;

	ofs = (p - data) - 2;

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
	pad		= ALIGN8(rec_len);
	rec_alloc	= rec_len + pad;
	orig_len	= *data_len;
	new_len		= orig_len + rec_alloc;

	mem = realloc(*data, new_len);
	if (!mem) {
		syslog(LOG_CRIT, "out of memory for data [%lu]", new_len);
		return false;
	}

	/* store 16-bit string length, little endian */
	p = mem + orig_len;
	raw_len = p;
	*raw_len = GUINT16_TO_LE(name_len);
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
	struct cld_msg_event me;
	cldino_t inum_le = cldino_to_le(inum);
	int gflags;
	struct session *sess;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &inum_le;
	key.size = sizeof(inum_le);

	memset(&me, 0, sizeof(me));
	memcpy(me.hdr.magic, CLD_MAGIC, sizeof(me.hdr.magic));
	me.hdr.op = cmo_event;

	rc = hand_idx->cursor(hand_idx, txn, &cur, 0);
	if (rc) {
		hand_idx->err(hand_idx, rc, "inode_notify cursor");
		return rc;
	}

	gflags = DB_SET;
	while (1) {
		struct raw_handle *h;

		rc = cur->get(cur, &key, &val, gflags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				hand_idx->err(hand_idx, rc,
					"inode_notify cursor get");
			break;
		}

		gflags = DB_NEXT_DUP;
		h = val.data;

		if (!deleted && !(GUINT32_FROM_LE(h->events) & CE_UPDATED))
			continue;

		sess = g_hash_table_lookup(cld_srv.sessions, h->sid);
		if (!sess) {
			syslog(LOG_WARNING, "inode_notify BUG");
			continue;
		}

		me.hdr.seqid = next_seqid_le(&sess->next_seqid_out);
		memcpy(me.hdr.sid, h->sid, sizeof(me.hdr.sid));
		strcpy(me.hdr.user, sess->user);
		me.fh = h->fh;
		me.events = GUINT32_TO_LE(deleted ? CE_DELETED : CE_UPDATED);

		if (!sess_sendmsg(sess, &me, sizeof(me), true))
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

	ino->time_modify = GUINT64_TO_LE(current_time.tv_sec);
	if (!ino->time_create)
		ino->time_create = ino->time_modify;
	ino->version = GUINT32_TO_LE(GUINT32_FROM_LE(ino->version) + 1);

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
	struct raw_lock *lock;
	uint32_t lflags;
	struct cld_msg_event me;
	struct session *sess;

	rc = db_locks->cursor(db_locks, txn, &cur, 0);
	if (rc) {
		db_locks->err(db_locks, rc, "db_locks->cursor");
		return rc;
	}

	memset(&key, 0, sizeof(key));

	/* key: inode number */
	key.data = &inum_le;
	key.size = sizeof(inum_le);

	memset(&me, 0, sizeof(me));
	memcpy(me.hdr.magic, CLD_MAGIC, sizeof(me.hdr.magic));
	me.hdr.op = cmo_event;

	/* loop through locks associated with this inode, searching
	 * for pending locks that can be converted into acquired
	 */
	gflags = DB_SET | DB_RMW;
	while (1) {
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

		lock = val.data;
		lflags = GUINT32_FROM_LE(lock->flags);

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

		sess = g_hash_table_lookup(cld_srv.sessions, lock->sid);
		if (!sess) {
			syslog(LOG_WARNING, "inode_lock_rescan BUG");
			break;
		}

		/*
		 * send lock acquisition notification to new lock holder
		 */

		me.hdr.seqid = next_seqid_le(&sess->next_seqid_out);
		memcpy(me.hdr.sid, lock->sid, sizeof(me.hdr.sid));
		strcpy(me.hdr.user, sess->user);
		me.fh = lock->fh;
		me.events = GUINT32_TO_LE(CE_LOCKED);

		if (!sess_sendmsg(sess, &me, sizeof(me), true))
			break;
	}

	cur->close(cur);
	return rc;
}

void msg_get(struct msg_params *mp, bool metadata_only)
{
	struct cld_msg_get *msg = mp->msg;
	struct cld_msg_get_resp *resp;
	size_t resp_len;
	uint64_t fh;
	struct raw_handle *h = NULL;
	struct raw_inode *inode = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	cldino_t inum;
	uint32_t name_len;
	uint32_t data_size, omode;
	void *data_mem = NULL;
	size_t data_mem_len = 0;
	int rc;
	struct session *sess = mp->sess;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	/* get filehandle from input msg */
	fh = GUINT64_FROM_LE(msg->fh);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = GUINT32_FROM_LE(h->mode);

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

	name_len = GUINT32_FROM_LE(inode->ino_len);
	data_size = GUINT32_FROM_LE(inode->size);

	resp_len = sizeof(*resp) + name_len + SHA_DIGEST_LENGTH;
	resp = malloc(resp_len);
	if (!resp) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	/* return response containing inode metadata */
	resp_copy(&resp->resp, &msg->hdr);
	resp->resp.hdr.seqid = next_seqid_le(&sess->next_seqid_out);
	resp->inum = GUINT64_TO_LE(inum);
	memcpy(&resp->ino_len, &inode->ino_len,
	       (sizeof(struct raw_inode) - sizeof(inode->inum)) + name_len);

	sess_sendmsg(sess, resp, resp_len, false);

	/* send one or more data packets, if necessary */
	if (!metadata_only) {
		int i, seg_len;
		void *p;
		char dbuf[CLD_MAX_UDP_SEG];
		struct cld_msg_data *dr = (struct cld_msg_data *) &dbuf;

		rc = cldb_data_get(txn, inum, &data_mem, &data_mem_len,
				   false, false);

		/* treat not-found as zero length file, as we may
		 * not yet have created the data record
		 */
		if (rc == DB_NOTFOUND) {
			data_mem = NULL;
			data_mem_len = 0;
		} else if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}

		/* copy the GET msg's hdr, then change op to DATA */
		memset(dr, 0, sizeof(*dr));
		memcpy(&dr->hdr.magic, CLD_MAGIC, CLD_MAGIC_SZ);
		memcpy(dr->hdr.sid, sess->sid, CLD_SID_SZ);
		strcpy(dr->hdr.user, sess->user);
		dr->hdr.op = cmo_data_c;

		i = 0;
		p = data_mem;

		/* break up data_mem into individual packets */
		while (data_mem_len > 0) {
			seg_len = MIN(CLD_MAX_UDP_SEG - sizeof(*dr), data_mem_len);

			dr->hdr.seqid = next_seqid_le(&sess->next_seqid_out);
			dr->strid = resp->resp.hdr.seqid;
			dr->seg = GUINT32_TO_LE(i);
			dr->seg_len = GUINT32_TO_LE(seg_len);
			memcpy(dbuf + sizeof(*dr), p, seg_len);

			i++;
			p += seg_len;
			data_mem_len -= seg_len;

			sess_sendmsg(sess, dr, seg_len + sizeof(*dr), true);
		}

		/* send terminating packet (seg_len == 0) */
		dr->hdr.seqid = next_seqid_le(&sess->next_seqid_out);
		dr->strid = resp->resp.hdr.seqid;
		dr->seg = GUINT32_TO_LE(i);
		dr->seg_len = 0;
		sess_sendmsg(sess, dr, sizeof(*dr), true);
	}

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get read-only txn commit");

	free(h);
	free(inode);
	free(data_mem);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, sess, &msg->hdr, resp_rc);
	free(h);
	free(inode);
	free(data_mem);
}

void msg_open(struct msg_params *mp)
{
	struct cld_msg_open *msg = mp->msg;
	struct cld_msg_open_resp resp;
	char *name;
	struct raw_session *raw_sess = NULL;
	struct raw_inode *inode = NULL, *parent = NULL;
	struct raw_handle *h;
	int rc, name_len;
	bool create, excl, do_dir, have_dir;
	struct pathname_info pinfo;
	void *parent_data = NULL;
	size_t parent_len;
	uint32_t msg_mode, msg_events;
	uint64_t fh;
	cldino_t inum;
	enum cle_err_codes resp_rc = CLE_OK;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	msg_mode = GUINT32_FROM_LE(msg->mode);
	msg_events = GUINT32_FROM_LE(msg->events);
	name_len = GUINT16_FROM_LE(msg->name_len);

	if (mp->msg_len < (sizeof(*msg) + name_len))
		return;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	name = mp->msg + sizeof(*msg);

	create = msg_mode & COM_CREATE;
	excl = msg_mode & COM_EXCL;
	do_dir = msg_mode & COM_DIRECTORY;

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
		resp_rc = CLE_INODE_INVAL;
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
	have_dir = GUINT32_FROM_LE(inode->flags) & CIFL_DIR;
	if (!create && (do_dir != have_dir)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	if (create) {
		/* create new in-memory inode */
		inode = cldb_inode_new(txn, name, name_len, 0);
		if (!inode) {
			syslog(LOG_CRIT, "cannot allocate new inode");
			resp_rc = CLE_OOM;
			goto err_out;
		}

		if (do_dir)
			inode->flags = GUINT32_TO_LE(
				GUINT32_FROM_LE(inode->flags) | CIFL_DIR);

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

		parent->size = GUINT32_TO_LE(parent_len);

		rc = inode_touch(txn, parent);
		if (rc) {
			resp_rc = CLE_DB_ERR;
			goto err_out;
		}
	}

	inum = cldino_from_le(inode->inum);

	/* alloc & init new handle; updates session's next_fh */
	h = cldb_handle_new(mp->sess, inum, msg_mode, msg_events);
	if (!h) {
		syslog(LOG_CRIT, "cannot allocate handle");
		resp_rc = CLE_OOM;
		goto err_out;
	}

	fh = GUINT64_FROM_LE(h->fh);

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
	raw_sess = session_new_raw(mp->sess);

	if (!raw_sess) {
		syslog(LOG_CRIT, "cannot allocate session");
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

	resp_copy(&resp.resp, &msg->hdr);
	resp.resp.hdr.seqid = next_seqid_le(&mp->sess->next_seqid_out);
	resp.resp.code = GUINT32_TO_LE(CLE_OK);
	resp.fh = GUINT64_TO_LE(fh);
	sess_sendmsg(mp->sess, &resp, sizeof(resp), true);

	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, mp->sess, &msg->hdr, resp_rc);
	free(parent_data);
	free(parent);
	free(inode);
	free(raw_sess);
}

void msg_put(struct msg_params *mp)
{
	struct cld_msg_put *msg = mp->msg;
	struct session *sess = mp->sess;
	uint64_t fh;
	struct raw_handle *h = NULL;
	struct raw_inode *inode = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	void *mem;
	int rc;
	cldino_t inum;
	uint32_t omode;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	fh = GUINT64_FROM_LE(msg->fh);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db, for validation */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = GUINT32_FROM_LE(h->mode);

	if ((!(omode & COM_WRITE)) ||
	    (omode & COM_DIRECTORY)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* read inode from db, for validation */
	rc = cldb_inode_get(txn, inum, &inode, false, 0);
	if (rc) {
		resp_rc = CLE_INODE_INVAL;
		goto err_out;
	}

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "msg_put read-only txn commit");

	/* copy message */
	mem = malloc(mp->msg_len);
	if (!mem) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	memcpy(mem, msg, mp->msg_len);

	/* store PUT message in PUT msg queue */
	sess->put_q = g_list_append(sess->put_q, mem);

	free(h);
	free(inode);
	resp_ok(mp->sock, sess, &msg->hdr);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, sess, &msg->hdr, resp_rc);
	free(h);
	free(inode);
}

static void try_commit_data(struct msg_params *mp,
			uint64_t strid, GList *pmsg_ent)
{
	struct cld_msg_put *pmsg = pmsg_ent->data;
	struct cld_msg_data *dmsg;
	GList *tmp, *tmp1;
	uint32_t data_size, tmp_size, tmp_seg = 0;
	int last_seg, nseg, rc, i;
	struct raw_handle *h = NULL;
	struct raw_inode *inode = NULL;
	cldino_t inum;
	uint64_t fh;
	enum cle_err_codes resp_rc = CLE_OK;
	void *mem, *p, *q;
	struct cld_msg_data **darr;
	struct session *sess = mp->sess;
	bool have_end_seg = false;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	data_size = GUINT32_FROM_LE(pmsg->data_size);
	tmp_size = 0;
	last_seg = 0;
	nseg = 0;

	/*
	 * Pass 1: count total size of all packets in our stream;
	 * count number of segments in stream.
	 */
	tmp = sess->data_q;
	while (tmp) {
		uint32_t tmp_seg, tmp_seg_len;

		dmsg = tmp->data;
		tmp = tmp->next;

		/* non-matching strid[] implies not-our-stream */
		if (dmsg->strid != strid)
			continue;

		tmp_seg = GUINT32_FROM_LE(dmsg->seg);
		if (tmp_seg >= CLD_MAX_DATA_MSGS)
			break;
		if (tmp_seg > last_seg)
			last_seg = tmp_seg;

		tmp_seg_len = GUINT32_FROM_LE(dmsg->seg_len);
		if (tmp_seg_len == 0)
			have_end_seg = true;
		else
			tmp_size += tmp_seg_len;
		nseg++;
		if (nseg > CLD_MAX_DATA_MSGS)
			break;
	}

	/* return if data stream not yet 100% received */
	if (!have_end_seg || tmp_size < data_size)
		return;		/* nothing to do */

	/* stream parameter bounds checking */
	if ((tmp_seg >= CLD_MAX_DATA_MSGS) ||
	    (nseg > CLD_MAX_DATA_MSGS) ||
	    (tmp_size > data_size)) {
		resp_rc = CLE_DATA_INVAL;
		goto err_out_noabort;
	}

	/* create array to store pointers to each data packet */
	darr = alloca(nseg * sizeof(struct cld_msg_data *));
	memset(darr, 0, nseg * sizeof(struct cld_msg_data *));

	sess->put_q = g_list_delete_link(sess->put_q, pmsg_ent);

	/*
	 * Pass 2: store packets in array, sorted by segment number
	 */
	tmp = sess->data_q;
	while (tmp) {
		dmsg = tmp->data;
		tmp1 = tmp;
		tmp = tmp->next;

		/* non-matching strid[] implies not-our-stream */
		if (dmsg->strid != strid)
			continue;

		/* remove data packet from data msg queue */
		sess->data_q = g_list_delete_link(sess->data_q, tmp1);

		tmp_seg = GUINT32_FROM_LE(dmsg->seg);

		/* prevent duplicate segment numbers */
		if (darr[tmp_seg]) {
			resp_rc = CLE_DATA_INVAL;
			goto err_out_noabort;
		}
		darr[tmp_seg] = dmsg;
	}

	/* final check for missing segments; if segments are missing
	 * at this point, it is a corrupted/malicious data stream,
	 * because it passed other checks following Pass #1
	 */
	for (i = 0; i < nseg; i++)
		if (!darr[i]) {
			resp_rc = CLE_DATA_INVAL;
			goto err_out_noabort;
		}

	fh = GUINT64_FROM_LE(pmsg->fh);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);

	/* read inode from db */
	rc = cldb_inode_get(txn, inum, &inode, false, DB_RMW);
	if (rc) {
		resp_rc = CLE_INODE_INVAL;
		goto err_out;
	}

	/* create contig. memory area sized to contain entire data stream */
	p = mem = malloc(data_size);
	if (!mem) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	/* loop through array, copying each data packet into contig. area */
	for (i = 0; i <= last_seg; i++) {
		dmsg = darr[i];
		q = dmsg;

		tmp_size = GUINT32_FROM_LE(dmsg->seg_len);
		memcpy(p, q + sizeof(*dmsg), tmp_size);
		p += tmp_size;

		free(dmsg);
	}

	/* store contig. data area in db */
	rc = cldb_data_put(txn, inum, mem, data_size, 0);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	inode->size = GUINT32_TO_LE(data_size);

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

	resp_ok(mp->sock, sess, &pmsg->hdr);
	free(pmsg);
	free(h);
	free(inode);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, sess, &pmsg->hdr, resp_rc);
	free(pmsg);
	free(h);
	free(inode);
}

void msg_data(struct msg_params *mp)
{
	struct cld_msg_data *msg = mp->msg;
	struct session *sess = mp->sess;
	GList *tmp;
	void *mem = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	uint32_t seg_len;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	seg_len = GUINT32_FROM_LE(msg->seg_len);

	if (mp->msg_len < (sizeof(*msg) + seg_len))
		return;

	/* search for PUT message with seqid == our strid; that is how we
	 * associate DATA messages with the initial PUT msg
	 */
	tmp = sess->put_q;
	while (tmp) {
		struct cld_msg_put *pmsg;

		pmsg = tmp->data;
		if (pmsg->hdr.seqid == msg->strid)
			break;

		tmp = tmp->next;
	}

	if (!tmp) {
		resp_rc = CLE_DATA_INVAL;
		goto err_out;
	}

	/* copy DATA msg */
	mem = malloc(mp->msg_len);
	if (!mem) {
		resp_rc = CLE_OOM;
		goto err_out;
	}

	memcpy(mem, mp->msg, mp->msg_len);

	/* store DATA message on DATA msg queue */
	sess->data_q = g_list_append(sess->data_q, mem);

	sess_sendmsg(sess, msg, sizeof(*msg), true);

	/* scan DATA queue for completed stream; commit to db, if found */
	try_commit_data(mp, msg->strid, tmp);
	return;

err_out:
	resp_err(mp->sock, sess, &msg->hdr, resp_rc);
}

void msg_close(struct msg_params *mp)
{
	struct cld_msg_close *msg = mp->msg;
	uint64_t fh;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	struct raw_handle *h = NULL;
	cldino_t lock_inum = 0;
	bool waiter = false;
	struct session *sess = mp->sess;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	fh = GUINT64_FROM_LE(msg->fh);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, DB_RMW);
	if (rc) {
		if (rc == DB_NOTFOUND)
			resp_rc = CLE_FH_INVAL;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	if (GUINT32_FROM_LE(h->mode) & COM_LOCK)
		lock_inum = cldino_from_le(h->inum);

	/* delete handle from db */
	rc = cldb_handle_del(txn, sess->sid, fh);
	if (rc) {
		resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* remove locks, if any */
	rc = session_remove_locks(txn, sess->sid, fh, lock_inum, &waiter);
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

	resp_ok(mp->sock, sess, &msg->hdr);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, sess, &msg->hdr, resp_rc);
	free(h);
}

void msg_del(struct msg_params *mp)
{
	struct cld_msg_del *msg = mp->msg;
	enum cle_err_codes resp_rc = CLE_OK;
	int rc, name_len;
	char *name;
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

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	name_len = GUINT16_FROM_LE(msg->name_len);

	if (mp->msg_len < (sizeof(*msg) + name_len))
		return;

	name = mp->msg + sizeof(*msg);

	if (!valid_inode_name(name, name_len) || (name_len < 2)) {
		resp_rc = CLE_NAME_INVAL;
		goto err_out_noabort;
	}

	pathname_parse(name, name_len, &pinfo);

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
	rc = cldb_inode_get_byname(txn, name, name_len, &ino, false, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			resp_rc = CLE_INODE_INVAL;
		else
			resp_rc = CLE_DB_ERR;
		goto err_out;
	}

	/* prevent deletion of non-empty dirs */
	if (GUINT32_FROM_LE(ino->flags) & CIFL_DIR) {
		DBT val;

		memset(&key, 0, sizeof(key));
		memset(&val, 0, sizeof(val));

		/* key: inode number */
		key.data = &ino->inum;
		key.size = sizeof(ino->inum);

		rc = db_data->get(db_data, txn, &key, &val, 0);
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
	if (!dirdata_delete(&parent_data, &parent_len,
			    pinfo.base, pinfo.base_len)) {
		syslog(LOG_WARNING, "dirent del failed");
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

	parent->size = GUINT32_TO_LE(parent_len);

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

	resp_ok(mp->sock, mp->sess, &msg->hdr);
	free(ino);
	free(parent);
	free(parent_data);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, mp->sess, &msg->hdr, resp_rc);
	free(ino);
	free(parent);
	free(parent_data);
}

void msg_unlock(struct msg_params *mp)
{
	struct cld_msg_unlock *msg = mp->msg;
	uint64_t fh;
	struct raw_handle *h = NULL;
	cldino_t inum;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	uint32_t omode;
	struct session *sess = mp->sess;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	fh = GUINT64_FROM_LE(msg->fh);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = GUINT32_FROM_LE(h->mode);

	if (!(omode & COM_LOCK)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* attempt to given lock on filehandle */
	rc = cldb_lock_del(txn, sess->sid, fh, inum);
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

	resp_ok(mp->sock, sess, &msg->hdr);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, sess, &msg->hdr, resp_rc);
	free(h);
}

void msg_lock(struct msg_params *mp, bool wait)
{
	struct cld_msg_lock *msg = mp->msg;
	uint64_t fh;
	struct raw_handle *h = NULL;
	cldino_t inum;
	int rc;
	enum cle_err_codes resp_rc = CLE_OK;
	uint32_t lock_flags, omode;
	bool acquired = false;
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	struct session *sess = mp->sess;

	/* make sure input data as large as expected */
	if (mp->msg_len < sizeof(*msg))
		return;

	fh = GUINT64_FROM_LE(msg->fh);
	lock_flags = GUINT32_FROM_LE(msg->flags);

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		resp_rc = CLE_DB_ERR;
		goto err_out_noabort;
	}

	/* read handle from db */
	rc = cldb_handle_get(txn, sess->sid, fh, &h, 0);
	if (rc) {
		resp_rc = CLE_FH_INVAL;
		goto err_out;
	}

	inum = cldino_from_le(h->inum);
	omode = GUINT32_FROM_LE(h->mode);

	if (!(omode & COM_LOCK)) {
		resp_rc = CLE_MODE_INVAL;
		goto err_out;
	}

	/* attempt to add lock */
	rc = cldb_lock_add(txn, sess->sid, fh, inum,
			   lock_flags & CLF_SHARED, wait, &acquired);
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
		goto err_out;
	}

	/* lock was acquired immediately */
	resp_ok(mp->sock, mp->sess, &msg->hdr);
	free(h);
	return;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "msg_get txn abort");
err_out_noabort:
	resp_err(mp->sock, mp->sess, &msg->hdr, resp_rc);
	free(h);
}



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
#include "cld.h"

struct pathname_info {
	char		*dir;
	size_t		dir_len;
	char		*base;
	size_t		base_len;
};

static void session_timeout(int fd, short events, void *userdata);

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

	lsl = memrchr(path, path_len, '/');
	ofs = lsl - path + 1;

	pinfo->dir = path;
	pinfo->dir_len = ofs - 1;
	pinfo->base = path + ofs;
	pinfo->base_len = path_len - ofs;
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
	if (!mem)
		return false;

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

guint sess_hash(gconstpointer v)
{
	const struct session *sess = v;
	const uint64_t *tmp = (const uint64_t *) sess->clid;

	return (guint) *tmp;
}

gboolean sess_equal(gconstpointer _a, gconstpointer _b)
{
	const struct session *a = _a;
	const struct session *b = _b;

	return (memcmp(a->clid, b->clid, CLD_CLID_SZ) == 0);
}

static struct session *session_new(void)
{
	struct session *sess;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return NULL;

	sess->handles = g_array_new(FALSE, FALSE, sizeof(uint64_t));

	evtimer_set(&sess->timer, session_timeout, sess);

	return sess;
}

static void session_encode(struct raw_session *raw, const struct session *sess)
{
	uint64_t *hsrc, *hdest;
	int i;
	void *p;

	memcpy(raw, sess, CLD_CLID_SZ + CLD_IPADDR_SZ);
	raw->last_contact = GUINT64_TO_LE(sess->last_contact);
	raw->next_fh = GUINT64_TO_LE(sess->next_fh);
	raw->n_handles = GUINT32_TO_LE(sess->handles->len);

	hsrc = (uint64_t *) sess->handles->data;

	p = raw;
	p += sizeof(*raw);
	hdest = p;

	for (i = 0; i < sess->handles->len; i++)
		hdest[i] = GUINT64_TO_LE(hsrc[i]);
}

static struct raw_session *session_new_raw(const struct session *sess)
{
	struct raw_session *raw_sess;
	size_t alloc_len;

	alloc_len = sizeof(*raw_sess) + (sizeof(uint64_t) * sess->handles->len);
	raw_sess = malloc(alloc_len);
	if (!raw_sess)
		return NULL;

	session_encode(raw_sess, sess);

	return raw_sess;
}

static bool inode_append(struct raw_inode **ino, struct raw_handle *h)
{
	size_t new_len, orig_len;
	void *mem, *p;
#if 0
	uint32_t n_handles;
#endif

	orig_len	= raw_ino_size(*ino);
	new_len		= orig_len + sizeof(struct raw_handle_key);

	mem = realloc(*ino, new_len);
	if (!mem)
		return false;

	p = mem + orig_len;
	memcpy(p, h, sizeof(struct raw_handle_key));

#if 0
	n_handles = GUINT32_FROM_LE((*ino)->n_handles);
	(*ino)->n_handles = GUINT32_TO_LE(n_handles + 1);
#endif

	return true;
}

bool msg_open(struct server_socket *sock, DB_TXN *txn, struct client *cli,
	      struct session *sess, uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_open *msg = (struct cld_msg_open *) raw_msg;
	char *name;
	struct raw_session *raw_sess = NULL;
	struct raw_inode *inode = NULL, *parent = NULL;
	struct raw_handle *h;
	int rc, name_len;
	bool create;
	struct pathname_info pinfo;
	void *parent_data = NULL;
	size_t parent_len;
	uint32_t msg_mode, msg_events;
	uint64_t fh;

	/* make sure input data as large as expected */
	if (msg_len < sizeof(*msg))
		return false;

	msg_mode = GUINT32_FROM_LE(msg->mode);
	msg_events = GUINT32_FROM_LE(msg->events);
	name_len = GUINT16_FROM_LE(msg->name_len);

	if (msg_len < (sizeof(*msg) + name_len))
		return false;

	name = (char *) raw_msg + sizeof(*msg);

	create = msg_mode & COM_CREATE;

	if (!valid_inode_name(name, name_len) || (create && name_len == 1)) {
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_NAME_INVAL);
		return false;
	}

	pathname_parse(name, name_len, &pinfo);

	/* read inode from db, if it exists */
	rc = cldb_inode_get(txn, name, name_len, &inode, true, true);
	if (rc && ((rc != DB_NOTFOUND) || (!create))) {
		resp_err(sock, cli, (struct cld_msg_hdr *) msg,
			(rc == DB_NOTFOUND) ? CLE_INODE_INVAL : CLE_DB_ERR);
		goto err_out;
	}

	if (create) {
		/* create new in-memory inode */
		inode = cldb_inode_new(pinfo.base, pinfo.base_len, 0);
		if (!inode) {
			syslog(LOG_CRIT, "out of memory");
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
			    CLE_OOM);
			goto err_out;
		}

		/* read parent, to which we will add new child inode */
		rc = cldb_inode_get(txn, pinfo.dir, pinfo.dir_len,
				    &parent, true, true);
		if (rc) {
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
				 CLE_DB_ERR);
			goto err_out;
		}

		/* read parent inode data, if any */
		rc = cldb_data_get(txn, pinfo.dir, pinfo.dir_len,
				   &parent_data, &parent_len, true, true);
		if (rc) {
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
				 CLE_DB_ERR);
			goto err_out;
		}

		/* append new record to inode's directory data */
		if (!dirdata_append(&parent_data, &parent_len,
				    pinfo.base, pinfo.base_len)) {
			syslog(LOG_CRIT, "out of memory");
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
			    CLE_OOM);
			goto err_out;
		}

		/* write parent inode's updated directory data */
		rc = cldb_data_put(txn, pinfo.dir, pinfo.dir_len,
				   parent_data, parent_len, 0);
		if (rc) {
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
				 CLE_DB_ERR);
			goto err_out;
		}

		parent->time_modify = GUINT64_TO_LE(current_time);
		parent->size = GUINT32_TO_LE(parent_len);

		/* write parent inode */
		rc = cldb_inode_put(txn, pinfo.dir, pinfo.dir_len,
				    parent, 0);
		if (rc) {
			resp_err(sock, cli, (struct cld_msg_hdr *) msg,
				 CLE_DB_ERR);
			goto err_out;
		}
	}

	/* alloc & init new handle; updates session's next_fh */
	h = cldb_handle_new(sess, name, name_len, msg_mode, msg_events);
	if (!h) {
		syslog(LOG_CRIT, "out of memory");
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_OOM);
		goto err_out;
	}

	fh = GUINT64_FROM_LE(h->fh);

	/* write newly created file handle */
	rc = cldb_handle_put(txn, h, 0);
	if (rc) {
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_DB_ERR);
		goto err_out;
	}

	g_array_append_val(sess->handles, fh);

	raw_sess = session_new_raw(sess);

	/* add handle to session, and to inode */
	if (!raw_sess || !inode_append(&inode, h)) {
		syslog(LOG_CRIT, "out of memory");
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_OOM);
		goto err_out;
	}

	inode->time_modify = GUINT64_TO_LE(current_time);

	/* write inode */
	rc = cldb_inode_put(txn, name, name_len, inode, 0);
	if (rc) {
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_DB_ERR);
		goto err_out;
	}

	/* write session */
	rc = cldb_session_put(txn, raw_sess, 0);
	if (rc) {
		resp_err(sock, cli, (struct cld_msg_hdr *) msg, CLE_DB_ERR);
		goto err_out;
	}

	free(parent_data);
	free(parent);
	free(inode);
	free(raw_sess);
	return true;

err_out:
	free(parent_data);
	free(parent);
	free(inode);
	free(raw_sess);
	return false;
}

static void session_timeout(int fd, short events, void *userdata)
{
	struct session *sess = userdata;

	/* FIXME */
	(void) sess;
}

bool msg_new_cli(struct server_socket *sock, DB_TXN *txn,
		 struct client *cli, uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_hdr *msg = (struct cld_msg_hdr *) raw_msg;
	DB *db = cld_srv.cldb.sessions;
	struct raw_session raw_sess;
	struct session *sess;
	DBT key, val;
	int rc;
	struct timeval tv;

	sess = session_new();
	if (!sess) {
		resp_err(sock, cli, msg, CLE_OOM);
		return false;
	}

	memcpy(&sess->clid, &msg->clid, sizeof(sess->clid));
	memcpy(&sess->addr, &cli->addr, sizeof(sess->addr));
	sess->addr_len = cli->addr_len;
	strncpy(sess->ipaddr, cli->addr_host, sizeof(sess->ipaddr));
	sess->last_contact = current_time;

	session_encode(&raw_sess, sess);

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &raw_sess.clid;
	key.size = sizeof(raw_sess.clid);

	val.data = &raw_sess;
	val.size = sizeof(raw_sess);

	rc = db->put(db, txn, &key, &val, DB_NOOVERWRITE);
	if (rc)
		goto err_out;

	g_hash_table_insert(cld_srv.sessions, sess->clid, sess);

	tv.tv_sec = CLD_CLI_TIMEOUT;
	tv.tv_usec = 0;
	if (evtimer_add(&sess->timer, &tv) < 0) {
		syslog(LOG_WARNING, "evtimer_add session_new failed");
		goto err_out;
	}

	resp_ok(sock, cli, msg);
	return true;

err_out:
	resp_err(sock, cli, msg, CLE_DB_ERR);
	free(sess);
	return false;
}


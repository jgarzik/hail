
#include "cld-config.h"

#include <string.h>
#include "cld.h"

bool msg_new_cli(struct server_socket *sock, DB_TXN *txn,
		 struct client *cli, uint8_t *raw_msg, size_t msg_len)
{
	struct cld_msg_hdr *msg = (struct cld_msg_hdr *) raw_msg;
	DB *db = cld_srv.cldb.sessions;
	struct raw_session sess;
	DBT key, val;
	int rc;

	memcpy(&sess.clid, &msg->clid, sizeof(sess.clid));
	strncpy(sess.addr, cli->addr_host, sizeof(sess.addr));
	sess.last_contact = GUINT64_TO_LE((uint64_t)time(NULL));

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = &sess.clid;
	key.size = sizeof(sess.clid);

	val.data = &sess;
	val.size = sizeof(sess);

	rc = db->put(db, txn, &key, &val, DB_NOOVERWRITE);
	if (rc) {
		resp_err(sock, cli, msg,
			(rc == DB_KEYEXIST) ? CLE_CLI_EXISTS : CLE_DB_ERR);
		return false;
	}

	resp_ok(sock, cli, msg);
	return true;
}


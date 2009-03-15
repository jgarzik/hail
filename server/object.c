#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/sha.h>
#include "chunkd.h"

bool object_del(struct client *cli)
{
	const char *basename = cli->creq.key;
	int rc;
	enum errcode err = InternalError;
	bool rcb;
	struct chunksrv_req *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	memcpy(resp, &cli->creq, sizeof(cli->creq));

	rcb = fs_obj_delete(basename, &err);
	if (!rcb)
		return cli_err(cli, err);

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		return true;
	}

	return cli_write_start(cli);
}

void cli_out_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->out_bo) {
		fs_obj_free(cli->out_bo);
		cli->out_bo = NULL;
	}

	free(cli->out_user);
	cli->out_user = NULL;
}

static bool object_put_end(struct client *cli)
{
	unsigned char md[SHA_DIGEST_LENGTH];
	char hashstr[50];
	int rc;
	enum errcode err = InternalError;
	bool rcb;
	struct chunksrv_req *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	memcpy(resp, &cli->creq, sizeof(cli->creq));

	cli->state = evt_recycle;

	SHA1_Final(md, &cli->out_hash);
	shastr(md, hashstr);

	rcb = fs_obj_write_commit(cli->out_bo, cli->out_user,
				  hashstr, cli->out_sync);
	if (!rcb)
		goto err_out;

	memcpy(resp->checksum, hashstr, sizeof(hashstr));
	resp->checksum[sizeof(hashstr)] = 0;

	cli_out_end(cli);

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		return true;
	}

	return cli_write_start(cli);

err_out:
	free(resp);
	cli_out_end(cli);
	return cli_err(cli, err);
}

bool cli_evt_data_in(struct client *cli, unsigned int events)
{
	char *p = cli->netbuf;
	ssize_t avail, bytes;

	if (!cli->out_len)
		return object_put_end(cli);

	if (cli->ssl) {
		int rc = SSL_read(cli->ssl, cli->netbuf,
				  MIN(cli->out_len, CLI_DATA_BUF_SZ));
		if (rc <= 0) {
			if (rc == 0) {
				cli->state = evt_dispose;
				return true;
			}

			rc = SSL_get_error(cli->ssl, rc);
			if (rc == SSL_ERROR_WANT_READ)
				return false;
			if (rc == SSL_ERROR_WANT_WRITE) {
				cli->read_want_write = true;
				if (event_add(&cli->write_ev, NULL) < 0)
					return cli_err(cli, InternalError);
				return false;
			}
			return cli_err(cli, InternalError);
		}
		avail = rc;
	} else {
		avail = read(cli->fd, cli->netbuf,
			     MIN(cli->out_len, CLI_DATA_BUF_SZ));
		if (avail <= 0) {
			if (avail == 0) {
				syslog(LOG_ERR, "object read(2) unexpected EOF");
				cli->state = evt_dispose;
				return true;
			}

			if (errno == EAGAIN)
				return false;

			cli_out_end(cli);
			syslog(LOG_ERR, "object read(2) error: %s",
					strerror(errno));
			return cli_err(cli, InternalError);
		}
	}

	while (avail > 0) {
		bytes = fs_obj_write(cli->out_bo, p, avail);
		if (bytes < 0) {
			cli_out_end(cli);
			return cli_err(cli, InternalError);
		}

		SHA1_Update(&cli->out_hash, cli->req_ptr, bytes);

		cli->out_len -= bytes;
		p += bytes;
		avail -= bytes;
	}

	if (!cli->out_len)
		return object_put_end(cli);

	return true;
}

bool object_put(struct client *cli)
{
	const char *user = cli->creq.user;
	const char *key = cli->creq.key;
	uint64_t content_len = GUINT64_FROM_LE(cli->creq.data_len);

	if (!user)
		return cli_err(cli, AccessDenied);
 
	cli->out_bo = fs_obj_new(key);
	if (!cli->out_bo)
		return cli_err(cli, InternalError);

	SHA1_Init(&cli->out_hash);
	cli->out_len = content_len;
	cli->out_user = strdup(user);
	cli->out_sync = true;

	if (!cli->out_len)
		return object_put_end(cli);

	cli->state = evt_data_in;

	return true;
}

void cli_in_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->in_obj) {
		fs_obj_free(cli->in_obj);
		cli->in_obj = NULL;
	}
}

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done)
{
	ssize_t bytes;

	/* do not queue more, if !completion or fd was closed early */
	if (!done)
		goto err_out_buf;

	bytes = fs_obj_read(cli->in_obj, cli->netbuf_out,
			  MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0)
		goto err_out;
	if (bytes == 0 && cli->in_len != 0)
		goto err_out;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	if (cli_writeq(cli, cli->netbuf_out, bytes,
		       cli->in_len ? object_get_more : NULL, NULL))
		goto err_out;

	return true;

err_out:
	cli_in_end(cli);
err_out_buf:
	return false;
}

bool object_get(struct client *cli, bool want_body)
{
	const char *basename = cli->creq.key;
	int rc;
	enum errcode err = InternalError;
	ssize_t bytes;
	struct backend_obj *obj;
	struct chunksrv_resp_get *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	memcpy(resp, &cli->creq, sizeof(cli->creq));

	obj = fs_obj_open(basename, &err);
	if (!obj)
		goto err_out;

	resp->req.data_len = GUINT32_TO_LE(obj->size);
	memcpy(resp->req.checksum, obj->hashstr, sizeof(obj->hashstr));
	resp->req.checksum[sizeof(obj->hashstr)] = 0;
	resp->mtime = GUINT64_TO_LE(obj->mtime);

	if (!want_body) {
		cli_in_end(cli);

		rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
		if (rc) {
			free(resp);
			return true;
		}
		goto start_write;
	}

	cli->in_len = obj->size;
	cli->in_obj = obj;

	bytes = fs_obj_read(cli->in_obj, cli->netbuf_out,
			  MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0)
		goto err_out_obj;
	if (bytes == 0 && cli->in_len != 0)
		goto err_out_obj;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		return true;
	}

	if (cli_writeq(cli, cli->netbuf_out, bytes,
		       cli->in_len ? object_get_more : NULL, NULL))
		goto err_out_obj;

start_write:
	return cli_write_start(cli);

err_out_obj:
	cli_in_end(cli);
err_out:
	free(resp);
	return cli_err(cli, err);
}


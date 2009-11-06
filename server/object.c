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
#include <chunk-private.h>
#include "chunkd.h"

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done);

bool object_del(struct client *cli)
{
	int rc;
	enum chunk_errcode err = che_InternalError;
	bool rcb;
	struct chunksrv_resp *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	resp_init_req(resp, &cli->creq);

	rcb = fs_obj_delete(cli->creq.user, cli->key, cli->key_len, &err);
	if (!rcb)
		return cli_err(cli, err, true);

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
	enum chunk_errcode err = che_InternalError;
	bool rcb;
	struct chunksrv_resp *resp = NULL;

	resp = malloc(sizeof(*resp));
	if (!resp) {
		cli->state = evt_dispose;
		return true;
	}

	resp_init_req(resp, &cli->creq);

	cli->state = evt_recycle;

	SHA1_Final(md, &cli->out_hash);
	hexstr(md, SHA_DIGEST_LENGTH, hashstr);

	rcb = fs_obj_write_commit(cli->out_bo, cli->out_user,
				  hashstr, (cli->creq.flags & CHF_SYNC));
	if (!rcb)
		goto err_out;

	memcpy(resp->checksum, hashstr, sizeof(hashstr));
	resp->checksum[sizeof(hashstr)] = 0;

	cli_out_end(cli);

	if (debugging)
		applog(LOG_DEBUG, "REQ(data-in) seq %x done code %d",
		       resp->nonce, resp->resp_code);

	rc = cli_writeq(cli, resp, sizeof(*resp), cli_cb_free, resp);
	if (rc) {
		free(resp);
		return true;
	}

	return cli_write_start(cli);

err_out:
	free(resp);
	cli_out_end(cli);
	return cli_err(cli, err, true);
}

bool cli_evt_data_in(struct client *cli, unsigned int events)
{
	char *p = cli->netbuf;
	ssize_t avail, bytes;
	size_t read_sz;

	if (!cli->out_len)
		return object_put_end(cli);

	read_sz = MIN(cli->out_len, CLI_DATA_BUF_SZ);

	if (debugging)
		applog(LOG_DEBUG, "REQ(data-in) seq %x, out_len %ld, read_sz %u",
		       cli->creq.nonce, cli->out_len, read_sz);

	if (cli->ssl) {
		int rc = SSL_read(cli->ssl, cli->netbuf, read_sz);
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
				if (!cli_wr_set_poll(cli, true))
					return cli_err(cli, che_InternalError, false);
				return false;
			}
			return cli_err(cli, che_InternalError, false);
		}
		avail = rc;
	} else {
		avail = read(cli->fd, cli->netbuf, read_sz);
		if (avail <= 0) {
			if (avail == 0) {
				applog(LOG_ERR, "object read(2) unexpected EOF");
				cli->state = evt_dispose;
				return true;
			}

			if (errno == EAGAIN) {
				if (debugging)
					applog(LOG_ERR, "object read(2) EAGAIN");
				return false;
			}

			cli_out_end(cli);
			applog(LOG_ERR, "object read(2) error: %s",
					strerror(errno));
			return cli_err(cli, che_InternalError, false);
		}
	}

	if (debugging && (avail != read_sz))
		applog(LOG_DEBUG, "REQ(data-in) avail %ld", (long)avail);

	while (avail > 0) {
		bytes = fs_obj_write(cli->out_bo, p, avail);
		if (bytes < 0) {
			cli_out_end(cli);
			return cli_err(cli, che_InternalError, false);
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
	uint64_t content_len = le64_to_cpu(cli->creq.data_len);
	enum chunk_errcode err;

	if (!user)
		return cli_err(cli, che_AccessDenied, true);

	cli->out_bo = fs_obj_new(cli->key, cli->key_len, &err);
	if (!cli->out_bo)
		return cli_err(cli, err, true);

	SHA1_Init(&cli->out_hash);
	cli->out_len = content_len;
	cli->out_user = strdup(user);

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

static bool object_read_bytes(struct client *cli)
{
	if (use_sendfile(cli)) {
		if (!cli_wr_sendfile(cli, object_get_more))
			return false;
	} else {
		ssize_t bytes;

		bytes = fs_obj_read(cli->in_obj, cli->netbuf_out,
				    MIN(cli->in_len, CLI_DATA_BUF_SZ));
		if (bytes < 0)
			return false;
		if (bytes == 0 && cli->in_len != 0)
			return false;

		cli->in_len -= bytes;

		if (!cli->in_len)
			cli_in_end(cli);

		if (cli_writeq(cli, cli->netbuf_out, bytes,
			       cli->in_len ? object_get_more : NULL, NULL))
			return false;
	}

	return true;
}

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done)
{
	/* do not queue more, if !completion or fd was closed early */
	if (!done)
		goto err_out_buf;

	if (!cli->in_len)
		cli_in_end(cli);
	else if (!object_read_bytes(cli))
		goto err_out;

	return true;

err_out:
	cli_in_end(cli);
err_out_buf:
	return false;
}

bool object_get(struct client *cli, bool want_body)
{
	int rc;
	enum chunk_errcode err = che_InternalError;
	struct backend_obj *obj;
	struct chunksrv_resp_get *get_resp = NULL;

	get_resp = calloc(1, sizeof(*get_resp));
	if (!get_resp) {
		cli->state = evt_dispose;
		return true;
	}

	resp_init_req(&get_resp->resp, &cli->creq);

	cli->in_obj = obj = fs_obj_open(cli->creq.user, cli->key,
					cli->key_len, &err);
	if (!obj) {
		free(get_resp);
		return cli_err(cli, err, true);
	}

	cli->in_len = obj->size;

	get_resp->resp.data_len = cpu_to_le64(obj->size);
	memcpy(get_resp->resp.checksum, obj->hashstr, sizeof(obj->hashstr));
	get_resp->resp.checksum[sizeof(obj->hashstr)] = 0;
	get_resp->mtime = cpu_to_le64(obj->mtime);

	rc = cli_writeq(cli, get_resp, sizeof(*get_resp), cli_cb_free, get_resp);
	if (rc) {
		free(get_resp);
		return true;
	}

	if (!want_body) {
		cli_in_end(cli);

		goto start_write;
	}

	if (!object_read_bytes(cli)) {
		cli_in_end(cli);
		return cli_err(cli, err, false);
	}

start_write:
	return cli_write_start(cli);
}


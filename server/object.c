#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/sha.h>
#include "storaged.h"

bool object_del(struct client *cli, const char *user,
		struct server_volume *vol, const char *basename)
{
	char timestr[50], *hdr;
	int rc;
	enum errcode err = InternalError;
	bool rcb;

	if (!vol)
		return cli_err(cli, NoSuchVolume);
	if (!user)
		return cli_err(cli, AccessDenied);

	rcb = vol->be->obj_delete(vol, cli->db, basename, &err);
	if (!rcb)
		return cli_err(cli, err);

	if (asprintf(&hdr,
"HTTP/%d.%d 204 x\r\n"
"Content-Length: 0\r\n"
"Date: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     time2str(timestr, time(NULL))) < 0)
		return cli_err(cli, InternalError);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);
}

void cli_out_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->out_bo) {
		g_assert(cli->out_vol != NULL);
		cli->out_vol->be->obj_free(cli->out_bo);
		cli->out_bo = NULL;
	}

	free(cli->out_user);
	cli->out_user = NULL;
}

static bool object_put_end(struct client *cli)
{
	unsigned char md[SHA_DIGEST_LENGTH];
	char hashstr[50], timestr[50];
	char *hdr;
	int rc;
	enum errcode err = InternalError;
	bool rcb;

	if (cli->req.pipeline)
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	SHA1_Final(md, &cli->out_hash);
	shastr(md, hashstr);

	rcb = cli->out_vol->be->obj_write_commit(cli->out_bo, cli->out_user,
						 hashstr, cli->out_sync);
	if (!rcb)
		goto err_out;

	if (asprintf(&hdr,
"HTTP/%d.%d 200 x\r\n"
"Content-Length: 0\r\n"
"ETag: \"%s\"\r\n"
"X-Volume-Key: %s\r\n"
"Date: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     hashstr,
		     cli->out_bo->cookie,
		     time2str(timestr, time(NULL))) < 0) {
		syslog(LOG_ERR, "OOM in object_put_end");
		goto err_out;
	}

	cli_out_end(cli);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out:
	cli_out_end(cli);
	return cli_err(cli, err);
}

bool cli_evt_http_data_in(struct client *cli, unsigned int events)
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
				cli->evt.events |= EPOLLOUT;
				cli->read_want_write = true;
				if (cli_epoll_mod(cli) < 0)
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
		bytes = cli->out_vol->be->obj_write(cli->out_bo, p, avail);
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

bool object_put(struct client *cli, const char *user,
		struct server_volume *vol,
		long content_len, bool expect_cont, bool sync_data)
{
	long avail;

	if (!vol)
		return cli_err(cli, NoSuchVolume);
	if (!user)
		return cli_err(cli, AccessDenied);
 
	cli->out_bo = vol->be->obj_new(vol, cli->db);
	if (!cli->out_bo)
		return cli_err(cli, InternalError);

	cli->out_vol = vol;
	SHA1_Init(&cli->out_hash);
	cli->out_len = content_len;
	cli->out_user = strdup(user);
	cli->out_sync = sync_data;

	/* handle Expect: 100-continue header, by unconditionally
	 * requesting that they continue.  At this point, the storage
	 * backend has verified that we may proceed.
	 */
	if (expect_cont) {
		char *cont;

		/* FIXME check for err */
		asprintf(&cont, "HTTP/%d.%d 100 Continue\r\n\r\n",
			 cli->req.major, cli->req.minor);
		cli_writeq(cli, cont, strlen(cont), cli_cb_free, cont);
		cli_write_start(cli);
	}

	avail = MIN(cli_req_avail(cli), content_len);
	if (avail) {
		ssize_t bytes;

		while (avail > 0) {
			bytes = vol->be->obj_write(cli->out_bo,
						   cli->req_ptr, avail);
			if (bytes < 0) {
				cli_out_end(cli);
				syslog(LOG_ERR, "write(2) error in object_put: %s",
					strerror(errno));
				return cli_err(cli, InternalError);
			}

			SHA1_Update(&cli->out_hash, cli->req_ptr, bytes);

			cli->out_len -= bytes;
			cli->req_ptr += bytes;
			avail -= bytes;
		}
	}

	if (!cli->out_len)
		return object_put_end(cli);

	cli->state = evt_http_data_in;
	return true;
}

void cli_in_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->in_obj) {
		g_assert(cli->in_vol != NULL);
		cli->in_vol->be->obj_free(cli->in_obj);
		cli->in_obj = NULL;
	}
}

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done)
{
	char *buf;
	ssize_t bytes;

	/* free now-written buffer */
	free(wr->cb_data);

	buf = malloc(CLI_DATA_BUF_SZ);
	if (!buf)
		return false;

	/* do not queue more, if !completion or fd was closed early */
	if (!done)
		goto err_out_buf;

	bytes = cli->in_vol->be->obj_read(cli->in_obj, buf,
					  MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0)
		goto err_out;
	if (bytes == 0 && cli->in_len != 0)
		goto err_out;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	if (cli_writeq(cli, buf, bytes,
		       cli->in_len ? object_get_more : cli_cb_free, buf))
		goto err_out;

	return true;

err_out:
	cli_in_end(cli);
err_out_buf:
	free(buf);
	return false;
}

bool object_get(struct client *cli, const char *user,
		struct server_volume *vol,
		const char *basename, bool want_body)
{
	char timestr[50], modstr[50], *hdr, *tmp;
	int rc;
	enum errcode err = InternalError;
	ssize_t bytes;
	bool modified = true;
	struct backend_obj *obj;

	if (!vol) {
		err = NoSuchVolume;
		goto err_out;
	}
	if (!user) {
		err = AccessDenied;
		goto err_out;
	}

	obj = vol->be->obj_open(vol, cli->db, basename, &err);
	if (!obj)
		goto err_out;

	hdr = req_hdr(&cli->req, "if-match");
	if (hdr && strcmp(obj->hashstr, hdr)) {
		err = PreconditionFailed;
		goto err_out_obj;
	}

	hdr = req_hdr(&cli->req, "if-unmodified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_obj;
		}

		if (obj->mtime > t) {
			err = PreconditionFailed;
			goto err_out_obj;
		}
	}

	hdr = req_hdr(&cli->req, "if-modified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_obj;
		}

		if (obj->mtime <= t) {
			modified = false;
			want_body = false;
		}
	}

	hdr = req_hdr(&cli->req, "if-none-match");
	if (hdr && (!strcmp(obj->hashstr, hdr))) {
		modified = false;
		want_body = false;
	}

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Length: %llu\r\n"
"ETag: \"%s\"\r\n"
"Date: %s\r\n"
"Last-Modified: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     modified ? 200 : 304,
		     (unsigned long long) obj->size,
		     obj->hashstr,
		     time2str(timestr, time(NULL)),
		     time2str(modstr, obj->mtime)) < 0)
		goto err_out_obj;

	if (!want_body) {
		cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			return true;
		}
		goto start_write;
	}

	cli->in_len = obj->size;
	cli->in_vol = vol;
	cli->in_obj = obj;

	bytes = vol->be->obj_read(cli->in_obj, cli->netbuf,
				  MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0)
		goto err_out_obj;
	if (bytes == 0 && cli->in_len != 0)
		goto err_out_obj;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	tmp = malloc(bytes);
	if (!tmp)
		goto err_out_obj;
	memcpy(tmp, cli->netbuf, bytes);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		free(tmp);
		return true;
	}

	if (cli_writeq(cli, tmp, bytes,
		       cli->in_len ? object_get_more : cli_cb_free, tmp))
		goto err_out_obj;

start_write:
	return cli_write_start(cli);

err_out_obj:
	cli_in_end(cli);
err_out:
	return cli_err(cli, err);
}


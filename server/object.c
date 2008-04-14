#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/sha.h>
#include "storaged.h"

static bool __object_del(const char *volume, const char *fn)
{
	int rc;
	sqlite3_stmt *stmt;

	/* delete object metadata */
	stmt = prep_stmts[st_del_obj];
	sqlite3_bind_text(stmt, 1, volume, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, fn, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL st_del_obj failed: %d", rc);
		return false;
	}

	return true;
}

bool object_del(struct client *cli, const char *user,
		struct server_volume *vol, const char *basename)
{
	char timestr[64], *hdr, *fn;
	int rc;
	enum errcode err = InternalError;
	sqlite3_stmt *stmt;
	char *volume;

	/* begin trans */
	if (!sql_begin()) {
		syslog(LOG_ERR, "SQL BEGIN failed in obj-del");
		return cli_err(cli, InternalError);
	}

	if (!user || !vol) {
		err = AccessDenied;
		goto err_out;
	}

	volume = vol->name;

	/* read existing object info, if any */
	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, volume, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, basename, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_reset(stmt);
		err = NoSuchKey;
		goto err_out;
	}

	sqlite3_reset(stmt);

	/* build data filename, for later use */
	fn = alloca(strlen(vol->path) + strlen(basename) + 2);
	sprintf(fn, "%s/%s", vol->path, basename);

	if (!__object_del(volume, basename))
		goto err_out;

	if (!sql_commit()) {
		syslog(LOG_ERR, "SQL COMMIT failed in obj-del");
		return cli_err(cli, InternalError);
	}

	if (unlink(fn) < 0)
		syslog(LOG_ERR, "object data(%s) unlink failed: %s",
		       fn, strerror(errno));
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

err_out:
	sql_rollback();
	return cli_err(cli, err);
}

void cli_out_end(struct client *cli)
{
	if (cli->out_fn) {
		unlink(cli->out_fn);
		free(cli->out_fn);
		cli->out_fn = NULL;
	}

	free(cli->out_user);

	cli->out_user = NULL;

	if (cli->out_fd >= 0) {
		close(cli->out_fd);
		cli->out_fd = -1;
	}
}

static bool object_put_end(struct client *cli)
{
	unsigned char md[SHA_DIGEST_LENGTH];
	char counter[64], hashstr[64], timestr[64];
	char *hdr, *fn = NULL;
	int rc;
	enum errcode err = InternalError;
	sqlite3_stmt *stmt;

	if (http11(&cli->req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	if (fsync(cli->out_fd) < 0) {
		syslog(LOG_ERR, "fsync(%s) failed: %s",
		       cli->out_fn, strerror(errno));
		goto err_out;
	}

	if (debugging) {
		struct stat sst;
		if (fstat(cli->out_fd, &sst) < 0)
			syslog(LOG_ERR, "fstat(%s) failed: %s",
			       cli->out_fn, strerror(errno));
		else
			syslog(LOG_DEBUG, "STORED %s, size %llu",
			       cli->out_fn,
			       (unsigned long long) sst.st_size);
	}

	close(cli->out_fd);
	cli->out_fd = -1;

	SHA1_Final(md, &cli->out_hash);

	sprintf(counter, "%016llX", (unsigned long long) cli->out_counter);
	shastr(md, hashstr);

	/* begin trans */
	if (!sql_begin()) {
		syslog(LOG_ERR, "SQL BEGIN failed in put-end");
		goto err_out;
	}

	/* read existing object info, if any */
	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, cli->out_vol->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, cli->out_fn, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);

	if (rc == SQLITE_ROW) {
		/* build data filename, for later use */
		const char *basename = (const char *)
			sqlite3_column_text(stmt, 2);
		fn = alloca(strlen(cli->out_vol->path) + strlen(basename) + 2);
		sprintf(fn, "%s/%s", cli->out_vol->path, basename);

		sqlite3_reset(stmt);

		/* delete object metadata */
		if (!__object_del(cli->out_vol->name, cli->out_fn)) {
			syslog(LOG_ERR, "old-obj(%s) delete failed", fn);
			goto err_out_rb;
		}
	} else
		sqlite3_reset(stmt);

	/* insert object */
	stmt = prep_stmts[st_add_obj];
	sqlite3_bind_text(stmt, 1, cli->out_vol->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, hashstr, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, counter, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, cli->out_user, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL INSERT(obj) failed");
		goto err_out_rb;
	}

	/* commit */
	if (!sql_commit()) {
		syslog(LOG_ERR, "SQL COMMIT");
		goto err_out;
	}

	if (fn && (unlink(fn) < 0))
		syslog(LOG_ERR, "object data(%s) unlink failed: %s",
		       fn, strerror(errno));

	free(cli->out_fn);
	free(cli->out_user);

	cli->out_user =
	cli->out_fn = NULL;

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
		     counter,
		     time2str(timestr, time(NULL))) < 0) {
		/* FIXME: cleanup failure */
		syslog(LOG_ERR, "OOM in object_put_end");
		return cli_err(cli, InternalError);
	}

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out_rb:
	sql_rollback();
err_out:
	cli_out_end(cli);
	return cli_err(cli, err);
}

bool cli_evt_http_data_in(struct client *cli, unsigned int events)
{
	char buf[4096];
	char *p = buf;
	ssize_t avail, bytes;

	if (!cli->out_len)
		return object_put_end(cli);

	avail = read(cli->fd, buf, MIN(cli->out_len, sizeof(buf)));
	if (avail <= 0) {
		if ((avail < 0) && (errno == EAGAIN))
			return false;

		cli_out_end(cli);
		if (avail < 0)
			syslog(LOG_ERR, "object read(2) error: %s",
				strerror(errno));
		else
			syslog(LOG_ERR, "object read(2) unexpected EOF");
		return cli_err(cli, InternalError);
	}

	while (avail > 0) {
		bytes = write(cli->out_fd, p, avail);
		if (bytes < 0) {
			cli_out_end(cli);
			syslog(LOG_ERR, "write(2) error in HTTP data-in: %s",
				strerror(errno));
			return cli_err(cli, InternalError);
		}

		SHA1_Update(&cli->out_hash, cli->req_ptr, bytes);

		cli->out_len -= bytes;
		p += bytes;
		avail -= bytes;
	}

	if (!cli->out_len)
		return object_put_end(cli);

	return (avail == sizeof(buf)) ? true : false;
}

bool object_put(struct client *cli, const char *user,
		struct server_volume *vol,
		long content_len, bool expect_cont)
{
	char *fn = NULL;
	long avail;
	char *volume;

	if (!user || !vol)
		return cli_err(cli, AccessDenied);
 
 	volume = vol->name;

	while (cli->out_fd < 0) {
		counter++;

		free(fn);

		if (asprintf(&fn, "%s/%016llX", vol->path,
			     (unsigned long long) counter) < 0) {
			syslog(LOG_ERR, "OOM in object_put");
			return cli_err(cli, InternalError);
		}

		cli->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}

	cli->out_fn = fn;
	cli->out_vol = vol;
	SHA1_Init(&cli->out_hash);
	cli->out_len = content_len;
	cli->out_counter = counter;
	cli->out_user = strdup(user);

	/* handle Expect: 100-continue header, by unconditionally
	 * requesting that they continue.
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
			bytes = write(cli->out_fd, cli->req_ptr, avail);
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

static void cli_in_end(struct client *cli)
{
	if (cli->in_fd >= 0) {
		close(cli->in_fd);
		cli->in_fd = -1;
	}

	free(cli->in_fn);

	cli->in_fn = NULL;
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
	if (!done || cli->in_fd < 0)
		goto err_out_buf;

	bytes = read(cli->in_fd, buf, MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0) {
		syslog(LOG_ERR, "read obj(%s) failed: %s", cli->in_fn,
			strerror(errno));
		goto err_out;
	}
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
	const char *hashstr;
	char timestr[64], modstr[64], *hdr, *fn, *tmp;
	int rc;
	enum errcode err = InternalError;
	struct stat st;
	char buf[4096];
	ssize_t bytes;
	sqlite3_stmt *stmt;
	bool modified = true;
	char *volume;

	if (!sql_begin())
		return cli_err(cli, InternalError);

	if (!user || !vol) {
		err = AccessDenied;
		goto err_out_rb;
	}

	volume = vol->name;

	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, volume, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, basename, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		err = NoSuchKey;
		goto err_out_reset;
	}

	hashstr = (const char *) sqlite3_column_text(stmt, 1);

	hdr = req_hdr(&cli->req, "if-match");
	if (hdr && strcmp(hashstr, hdr)) {
		err = PreconditionFailed;
		goto err_out_reset;
	}

	if (asprintf(&fn, "%s/%s", vol->path, basename) < 0)
		goto err_out_str;

	cli->in_fd = open(fn, O_RDONLY);
	if (cli->in_fd < 0) {
		free(fn);
		syslog(LOG_ERR, "open obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_str;
	}

	cli->in_fn = fn;

	if (fstat(cli->in_fd, &st) < 0) {
		syslog(LOG_ERR, "fstat obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_in_end;
	}

	hdr = req_hdr(&cli->req, "if-unmodified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_in_end;
		}

		if (st.st_mtime > t) {
			err = PreconditionFailed;
			goto err_out_in_end;
		}
	}

	hdr = req_hdr(&cli->req, "if-modified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_in_end;
		}

		if (st.st_mtime <= t) {
			modified = false;
			want_body = false;
		}
	}

	hdr = req_hdr(&cli->req, "if-none-match");
	if (hdr && (!strcmp(hashstr, hdr))) {
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
		     (unsigned long long) st.st_size,
		     hashstr,
		     time2str(timestr, time(NULL)),
		     time2str(modstr, st.st_mtime)) < 0)
		goto err_out_in_end;

	if (!want_body) {
		cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			return true;
		}
		goto start_write;
	}

	cli->in_len = st.st_size;

	bytes = read(cli->in_fd, buf, MIN(st.st_size, sizeof(buf)));
	if (bytes < 0) {
		syslog(LOG_ERR, "read obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_in_end;
	}
	if (bytes == 0 && cli->in_len != 0)
		goto err_out_in_end;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	tmp = malloc(bytes);
	if (!tmp)
		goto err_out_in_end;
	memcpy(tmp, buf, bytes);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		free(tmp);
		return true;
	}

	if (cli_writeq(cli, tmp, bytes,
		       cli->in_len ? object_get_more : cli_cb_free, tmp))
		goto err_out_in_end;

start_write:
	sqlite3_reset(prep_stmts[st_object]);
	sql_commit();
	return cli_write_start(cli);

err_out_in_end:
	cli_in_end(cli);
err_out_str:
err_out_reset:
	sqlite3_reset(prep_stmts[st_object]);
err_out_rb:
	sql_rollback();
	return cli_err(cli, err);
}


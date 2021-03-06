
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <libxml/tree.h>
#include <glib.h>
#include <chunkc.h>
#include <netdb.h>
#include <chunk-private.h>
#include <chunk_msg.h>
#include <chunksrv.h>
#include <errno.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#if 0
static int _strcasecmp(const unsigned char *a, const char *b)
{
	return xmlStrcasecmp(a, (const unsigned char *) b);
}
#endif

static int _strcmp(const unsigned char *a, const char *b)
{
	return xmlStrcmp(a, (const unsigned char *) b);
}

static bool key_valid(const void *key, size_t key_len)
{
	if (!key || key_len < 1 || key_len > CHD_KEY_SZ)
		return false;
	
	return true;
}

static void req_init(struct st_client *stc, struct chunksrv_req *req)
{
	memset(req, 0, sizeof(*req));
	memcpy(req->magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req->nonce = rand();
}

static void req_set_key(struct chunksrv_req *req, const void *key,
			uint16_t key_len)
{
	req->key_len = GUINT16_TO_LE(key_len);
	memcpy((req + 1), key, key_len);
}

static bool net_read(struct st_client *stc, void *data, size_t datalen)
{
	if (!datalen)
		return true;

	if (stc->ssl) {
		int rc;

		while (datalen) {
			rc = SSL_read(stc->ssl, data, datalen);
			if (rc <= 0)
				return false;
			datalen -= rc;
			data += rc;
		}
	} else {
		ssize_t rc;

		while (datalen) {
			rc = read(stc->fd, data, datalen);
			if (rc <= 0)
				return false;
			datalen -= rc;
			data += rc;
		}
	}

	return true;
}

static bool net_write(struct st_client *stc, const void *data, size_t datalen)
{
	if (!datalen)
		return true;

	if (stc->ssl) {
		int rc;

		while (datalen) {
			rc = SSL_write(stc->ssl, data, datalen);
			if (rc < 0)
				return false;
			datalen -= rc;
			data += rc;
		}
	} else {
		ssize_t rc;

		while (datalen) {
			rc = write(stc->fd, data, datalen);
			if (rc < 0)
				return false;
			datalen -= rc;
			data += rc;
		}
	}

	return true;
}

static bool resp_valid(const struct chunksrv_resp *resp)
{
	if (memcmp(resp->magic, CHUNKD_MAGIC, CHD_MAGIC_SZ))
		return false;

	return true;
}

static bool resp_read(struct st_client *stc, struct chunksrv_resp *resp)
{
	/* read and validate response header */
	if (!net_read(stc, resp, sizeof(*resp)) ||
	    !resp_valid(resp))
		return false;

	return true;
}

void stc_free(struct st_client *stc)
{
	if (!stc)
		return;

	free(stc->host);
	free(stc->user);
	free(stc->key);
	if (stc->ssl) {
		SSL_shutdown(stc->ssl);
		SSL_free(stc->ssl);
	}
	if (stc->ssl_ctx)
		SSL_CTX_free(stc->ssl_ctx);
	if (stc->fd >= 0)
		close(stc->fd);
	free(stc);
}

static bool stc_login(struct st_client *stc)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: LOGIN\n");

	/* initialize request; username is sent as key/key_len */
	req_init(stc, req);
	req->op = CHO_LOGIN;
	req_set_key(req, stc->user, strlen(stc->user) + 1);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "LOGIN failed, resp code: %d\n",
				resp.resp_code);
		return false;
	}

	return true;
}

static bool stc_start_tls_cmd(struct st_client *stc)
{
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: START-TLS\n");

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_START_TLS;
	strcpy(req->sig, "START-TLS");

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* no response - SSL negotiation begins immediately */

	return true;
}

struct st_client *stc_new(const char *service_host, int port,
			  const char *user, const char *secret_key,
			  bool use_ssl)
{
	struct st_client *stc;
	struct addrinfo hints, *res = NULL, *rp;
	int rc, fd = -1, on = 1;
	char port_str[32];

	if (!service_host || !*service_host ||
	    port < 1 || port > 65535 ||
	    !user || !*user ||
	    !secret_key || !*secret_key)
		return NULL;

	sprintf(port_str, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(service_host, port_str, &hints, &res);
	if (rc) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		return NULL;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) {
			perror("socket");
			continue;
		}

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(fd);
	}

	freeaddrinfo(res);

	if (!rp)
		return NULL;

	/* disable delay of small output packets */
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		perror("setsockopt(TCP_NODELAY)");

	stc = calloc(1, sizeof(struct st_client));
	if (!stc)
		return NULL;

	stc->fd = fd;
	stc->host = strdup(service_host);
	stc->user = strdup(user);
	stc->key = strdup(secret_key);

	if (!stc->host || !stc->user || !stc->key)
		goto err_out;

	if (use_ssl) {
		if (!stc_start_tls_cmd(stc))
			goto err_out;

		stc->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		if (!stc->ssl_ctx)
			goto err_out;

		SSL_CTX_set_mode(stc->ssl_ctx, SSL_MODE_AUTO_RETRY);

		stc->ssl = SSL_new(stc->ssl_ctx);
		if (!stc->ssl)
			goto err_out_ctx;

		if (!SSL_set_fd(stc->ssl, stc->fd))
			goto err_out_ssl;

		rc = SSL_connect(stc->ssl);
		if (rc <= 0)
			goto err_out_ssl;
	}

	if (!stc_login(stc))
		goto err_out_ssl;

	return stc;

err_out_ssl:
	if (stc->ssl) {
		SSL_free(stc->ssl);
		stc->ssl = NULL;
	}
err_out_ctx:
	if (stc->ssl_ctx) {
		SSL_CTX_free(stc->ssl_ctx);
		stc->ssl_ctx = NULL;
	}
err_out:
	close(stc->fd);
	stc_free(stc);
	return NULL;
}

static size_t all_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	GByteArray *all_data = user_data;
	int len = size * nmemb;

	g_byte_array_append(all_data, ptr, len);

	return len;
}

/*
 * Request the transfer in the chunk server.
 */
static bool stc_get_req(struct st_client *stc, const void *key,
			size_t key_len, uint64_t *plen)
{
	struct chunksrv_resp_get get_resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: GET(%u)\n", (unsigned int) key_len);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_GET;
	req_set_key(req, key, key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &get_resp.resp))
		return false;

	/* check response code */
	if (get_resp.resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "GET resp code: %d\n", get_resp.resp.resp_code);
		return false;
	}

	/* read rest of response header */
	if (!net_read(stc, &get_resp.mtime,
		      sizeof(get_resp) - sizeof(get_resp.resp)))
		return false;

	*plen = le64_to_cpu(get_resp.resp.data_len);
	return true;
}

bool stc_get(struct st_client *stc, const void *key, size_t key_len,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data)
{
	char netbuf[4096];
	uint64_t content_len;

	if (!stc_get_req(stc, key, key_len, &content_len))
		return false;

	/* read response data */
	while (content_len) {
		size_t xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		if (!net_read(stc, netbuf, xfer_len))
			return false;

		write_cb(netbuf, xfer_len, 1, user_data);
		content_len -= xfer_len;
	}

	return true;
}

void *stc_get_inline(struct st_client *stc, const void *key,
		     size_t key_len, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = stc_get(stc, key, key_len, all_data_cb, all_data);
	if (!rcb) {
		g_byte_array_free(all_data, TRUE);
		return NULL;
	}

	if (len)
		*len = all_data->len;

	mem = all_data->data;

	g_byte_array_free(all_data, FALSE);
	return mem;
}

/*
 * Set stc to be used for streaming transfers.
 * In chunkd protocol, this delivers the size of the presumed object,
 * and clients are expected to fetch exactly psize amount.
 */
bool stc_get_start(struct st_client *stc, const void *key, size_t key_len,
		   int *pfd, uint64_t *psize)
{

	if (!stc_get_req(stc, key, key_len, psize))
		return false;

	*pfd = stc->fd;
	return true;
}

/*
 * Get next chunk for the stream set by stc_get_start.
 * N.B.: This should be called and will not block, even if no data was
 * reported on the fd by the OS. This is the only sane way to fetch what
 * SSL layer may keep buffered.
 * Therefore, we cannot use zero return as an EOF indicator and will
 * return a -EPIPE (normally not possible on read in UNIX). Fortunately,
 * applications know the object lengths as reported by stc_get_start.
 */
size_t stc_get_recv(struct st_client *stc, void *data, size_t data_len)
{
	size_t xfer_len;
	size_t done_cnt;
	int avail;
	ssize_t rc;

	done_cnt = 0;
	if (stc->ssl) {
		for (;;) {
			if (done_cnt == data_len)
				break;
			if (ioctl(stc->fd, FIONREAD, &avail))
				return -errno;
			if (avail == 0) {
				if ((avail = SSL_pending(stc->ssl)) == 0)
					break;
			}

			if ((xfer_len = avail) > data_len - done_cnt)
				xfer_len = data_len - done_cnt;

			rc = SSL_read(stc->ssl, data + done_cnt, xfer_len);
			if (rc <= 0) {
				if (done_cnt)
					break;
				rc = SSL_get_error(stc->ssl, rc);
				if (rc == SSL_ERROR_ZERO_RETURN)
					return -EPIPE;
				if (rc == SSL_ERROR_WANT_READ ||
				    rc == SSL_ERROR_WANT_WRITE)
					continue;
				return -EIO;
			}

			done_cnt += rc;
		}
	} else {
		if (ioctl(stc->fd, FIONREAD, &avail))
			return -errno;
		if (avail) {
			if ((xfer_len = avail) > data_len)
				xfer_len = data_len;

			rc = read(stc->fd, data, xfer_len);
			if (rc < 0)
				return -errno;

			done_cnt += rc;
		}
	}
	return done_cnt;
}

/*
 * Request the transfer in the chunk server.
 */
static bool stc_get_part_req(struct st_client *stc, const void *key,
			size_t key_len, uint64_t offset, uint64_t max_len,
			uint64_t *plen)
{
	struct chunksrv_resp_get get_resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;
	struct chunksrv_req_getpart gpr;

	if (stc->verbose)
		fprintf(stderr, "libstc: GET_PART(%u, %llu, %llu)\n",
			(unsigned int) key_len,
			(unsigned long long) offset,
			(unsigned long long) max_len);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_GET_PART;
	req->data_len = cpu_to_le64(max_len);
	req_set_key(req, key, key_len);

	gpr.offset = cpu_to_le64(offset);
	memcpy(stc->req_buf + sizeof(struct chunksrv_req) + key_len,
	       &gpr, sizeof(struct chunksrv_req_getpart));

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &get_resp.resp))
		return false;

	/* check response code */
	if (get_resp.resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "GET resp code: %d\n", get_resp.resp.resp_code);
		return false;
	}

	/* read rest of response header */
	if (!net_read(stc, &get_resp.mtime,
		      sizeof(get_resp) - sizeof(get_resp.resp)))
		return false;

	*plen = le64_to_cpu(get_resp.resp.data_len);
	return true;
}

bool stc_get_part(struct st_client *stc, const void *key, size_t key_len,
	     uint64_t offset, uint64_t max_len,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data)
{
	char netbuf[4096];
	uint64_t content_len;

	if (!stc_get_part_req(stc, key, key_len, offset, max_len, &content_len))
		return false;

	/* read response data */
	while (content_len) {
		size_t xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		if (!net_read(stc, netbuf, xfer_len))
			return false;

		write_cb(netbuf, xfer_len, 1, user_data);
		content_len -= xfer_len;
	}

	return true;
}

/*
 * Set stc to be used for streaming transfers.
 * In chunkd protocol, this delivers the size of the presumed object,
 * and clients are expected to fetch exactly psize amount.
 */
bool stc_get_part_start(struct st_client *stc, const void *key, size_t key_len,
		   uint64_t offset, uint64_t max_len,
		   int *pfd, uint64_t *psize)
{

	if (!stc_get_part_req(stc, key, key_len, offset, max_len, psize))
		return false;

	*pfd = stc->fd;
	return true;
}

void *stc_get_part_inline(struct st_client *stc, const void *key,
		     size_t key_len, uint64_t offset, uint64_t max_len,
		     size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = stc_get_part(stc, key, key_len, offset, max_len,
			   all_data_cb, all_data);
	if (!rcb) {
		g_byte_array_free(all_data, TRUE);
		return NULL;
	}

	if (len)
		*len = all_data->len;

	mem = all_data->data;

	g_byte_array_free(all_data, FALSE);
	return mem;
}

bool stc_table_open(struct st_client *stc, const void *key, size_t key_len,
		    uint32_t flags)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: TABLE OPEN(%u, %u)\n",
			(unsigned int) key_len,
			flags);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_TABLE_OPEN;
	req->flags = (flags & (CHF_TBL_CREAT | CHF_TBL_EXCL));
	req_set_key(req, key, key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "TABLE OPEN resp code: %d\n",
				resp.resp_code);
		return false;
	}

	return true;
}

bool stc_put(struct st_client *stc, const void *key, size_t key_len,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, uint32_t flags)
{
	char netbuf[4096];
	struct chunksrv_resp resp;
	uint64_t content_len = len;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: PUT(%u, %Lu)\n",
			(unsigned int) key_len,
			(unsigned long long) len);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_PUT;
	req->flags = (flags & CHF_SYNC);
	req->data_len = cpu_to_le64(content_len);
	req_set_key(req, key, key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		goto err_out;

	while (content_len) {
		size_t rrc;
		size_t xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		rrc = read_cb(netbuf, xfer_len, 1, user_data);
		if (rrc < 1)
			goto err_out;

		content_len -= rrc;

		if (!net_write(stc, netbuf, rrc))
			goto err_out;
	}

	/* read response header */
	if (!resp_read(stc, &resp))
		goto err_out;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "PUT resp code: %d\n", resp.resp_code);
		goto err_out;
	}

	return true;

err_out:
	return false;
}

/*
 * Start quasy-asynchronous putting. Only one such putting
 * may be outstanding at a time for every st_client.
 *
 * We return the fd for the polling here because we do not like
 * library users poking around stc->fd, an implementation detail.
 */
bool stc_put_start(struct st_client *stc, const void *key, size_t key_len,
		   uint64_t cont_len, int *pfd, uint32_t flags)
{
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: PUT(%u, %Lu) start\n",
			(unsigned int) key_len,
			(unsigned long long) cont_len);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_PUT;
	req->flags = (flags & CHF_SYNC);
	req->data_len = cpu_to_le64(cont_len);
	req_set_key(req, key, key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		goto err_out;

	*pfd = stc->fd;
	return true;

err_out:
	return false;
}

/*
 * Try to send a chunk of data after stc_put_start.
 *
 * This commonly returns less then was requested, in order to allow
 * libevent-driven programs to function without undue blocking.
 * Don't be alarmed, use the fd returned from stc_put_start to know
 * when to retry.
 *
 * We probably should check that the sum of all len equals to what we
 * sent to chunkd in stc_put_start, but oh well. Don't overrun.
 */
size_t stc_put_send(struct st_client *stc, void *data, size_t len)
{
	size_t done_cnt;
	ssize_t rc;

	if (!len)
		return 0;

	if (stc->ssl) {
		done_cnt = 0;

		while (len) {
			rc = SSL_write(stc->ssl, data, len);
			if (rc <= 0) {
				rc = SSL_get_error(stc->ssl, rc);
				if (rc == SSL_ERROR_ZERO_RETURN)
					return -EPIPE;
				if (rc == SSL_ERROR_WANT_READ)
					continue;
				if (rc == SSL_ERROR_WANT_WRITE)
					break;
				return -EIO;
			}

			len -= rc;
			data += rc;
			done_cnt += rc;
		}
	} else {
		rc = write(stc->fd, data, len);
		if (rc < 0)
			return -errno;
		done_cnt = rc;
	}
	return done_cnt;
}

/*
 * Finish what stc_put_start began. The return code reports if the
 * request was processed by chunkd. No matter what, once this returns,
 * the st_client can accept new stc_put_start.
 */
bool stc_put_sync(struct st_client *stc)
{
	struct chunksrv_resp resp;

	/* read response header */
	if (!resp_read(stc, &resp))
		goto err_out;

	/* check response code */
	if (stc->verbose)
		fprintf(stderr, "libstc: PUT sync resp code: %d\n",
			resp.resp_code);
	if (resp.resp_code != che_Success)
		goto err_out;

	return true;

err_out:
	return false;
}

struct stc_put_info {
	void		*data;
	uint64_t	len;
};

static size_t read_inline_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct stc_put_info *spi = user_data;
	size_t n_bytes = size * nmemb;
	size_t len;

	len = MIN(n_bytes, spi->len);
	if (len) {
		memcpy(ptr, spi->data, len);
		spi->data += len;
		spi->len -= len;
	}

	return len;
}

bool stc_put_inline(struct st_client *stc, const void *key, size_t key_len,
	     void *data, uint64_t len, uint32_t flags)
{
	struct stc_put_info spi = { data, len };

	return stc_put(stc, key, key_len, read_inline_cb, len, &spi, flags);
}

bool stc_del(struct st_client *stc, const void *key, size_t key_len)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: DEL(%u)\n",
			(unsigned int) key_len);

	if (!key_valid(key, key_len))
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_DEL;
	req_set_key(req, key, key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "DEL resp code: %d\n", resp.resp_code);
		return false;
	}

	return true;
}

void stc_free_object(struct st_object *obj)
{
	if (!obj)
		return;

	free(obj->name);
	free(obj->time_mod);
	free(obj->etag);
	free(obj->owner);
	free(obj);
}

void stc_free_keylist(struct st_keylist *keylist)
{
	GList *tmp;

	if (!keylist)
		return;

	free(keylist->name);

	tmp = keylist->contents;
	while (tmp) {
		stc_free_object(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(keylist->contents);

	free(keylist);
}

static void stc_parse_key(xmlDocPtr doc, xmlNode *node,
			  struct st_keylist *keylist)
{
	struct st_object *obj;
	xmlChar *xs;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return;

	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Name")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->name = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "LastModified")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->time_mod = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "ETag")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->etag = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Size")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->size = atoll((char *) xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Owner")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->owner = strdup((char *)xs);
			xmlFree(xs);
		}

		node = node->next;
	}

	if (obj->name)
		keylist->contents = g_list_append(keylist->contents, obj);
	else
		stc_free_object(obj);
}

struct st_keylist *stc_keys(struct st_client *stc)
{
	struct st_keylist *keylist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	char netbuf[4096];
	struct chunksrv_resp resp;
	uint64_t content_len;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: LIST-KEYS\n");

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_LIST;

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "LIST resp code: %d\n", resp.resp_code);
		return false;
	}

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	content_len = le64_to_cpu(resp.data_len);

	/* read response data */
	while (content_len) {
		size_t xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		if (!net_read(stc, netbuf, xfer_len))
			goto err_out;

		g_byte_array_append(all_data, (unsigned char *)netbuf, xfer_len);
		content_len -= xfer_len;
	}

	doc = xmlReadMemory((char *) all_data->data, all_data->len,
			    "foo.xml", NULL, 0);
	if (!doc)
		goto err_out;

	node = xmlDocGetRootElement(doc);
	if (!node)
		goto err_out_doc;

	if (_strcmp(node->name, "ListVolumeResult"))
		goto err_out_doc;

	keylist = calloc(1, sizeof(*keylist));
	if (!keylist)
		goto err_out_doc;

	node = node->children;
	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Name")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->name = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Contents"))
			stc_parse_key(doc, node->children, keylist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;

	return keylist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;
	return NULL;
}

bool stc_ping(struct st_client *stc)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: PING\n");

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_NOP;

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "NOP resp code: %d\n", resp.resp_code);
		return false;
	}

	return true;
}

bool stc_check_start(struct st_client *stc)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req = (struct chunksrv_req *) stc->req_buf;

	if (stc->verbose)
		fprintf(stderr, "libstc: CHECK_START\n");

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_CHECK_START;

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, req_len(req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "CHECK_START resp code: %d\n",
				resp.resp_code);
		return false;
	}

	return true;
}

bool stc_check_status(struct st_client *stc, struct chunk_check_status *out)
{
	struct chunksrv_resp resp;
	struct chunksrv_req req;
	uint64_t content_len;

	if (stc->verbose)
		fprintf(stderr, "libstc: CHECK_STATUS\n");

	/* initialize request */
	req_init(stc, &req);
	req.op = CHO_CHECK_STATUS;

	/* sign request */
	chreq_sign(&req, stc->key, req.sig);

	/* write request */
	if (!net_write(stc, &req, req_len(&req)))
		return false;

	/* read response header */
	if (!resp_read(stc, &resp))
		return false;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "CHECK STATUS resp code: %d\n",
				resp.resp_code);
		return false;
	}

	content_len = le64_to_cpu(resp.data_len);
	if (content_len != sizeof(struct chunk_check_status)) {
		if (stc->verbose)
			fprintf(stderr, "CHECK STATUS bogus length: %lld\n",
				(long long) content_len);
		/* XXX And the unread data in the pipe, what about it? */
		return false;
	}

	/* read response data */
	if (!net_read(stc, out, content_len))
		return false;

	return true;
}

bool stc_cp(struct st_client *stc,
	    const void *dest_key, size_t dest_key_len,
	    const void *src_key, size_t src_key_len)
{
	struct chunksrv_resp resp;
	struct chunksrv_req *req;
	void *p;
	bool rcb = false;
	size_t alloc_len;

	if (stc->verbose)
		fprintf(stderr, "libstc: CP\n");

	alloc_len = sizeof(*req) + src_key_len + dest_key_len;
	req = malloc(alloc_len);
	if (!req)
		return false;

	/* initialize request */
	req_init(stc, req);
	req->op = CHO_CP;
	req->data_len = cpu_to_le64(src_key_len);

	/* store destination (new) key in key (1st) buffer area */
	req_set_key(req, dest_key, dest_key_len);

	/* store source (old) key in data (2nd) buffer area */
	p = (req + 1);
	p += dest_key_len;
	memcpy(p, src_key, src_key_len);

	/* sign request */
	chreq_sign(req, stc->key, req->sig);

	/* write request */
	if (!net_write(stc, req, alloc_len))
		goto out;

	/* read response header */
	if (!resp_read(stc, &resp))
		goto out;

	/* check response code */
	if (resp.resp_code != che_Success) {
		if (stc->verbose)
			fprintf(stderr, "CP resp code: %d\n", resp.resp_code);
		goto out;
	}

	rcb = true;

out:
	free(req);
	return rcb;
}

/*
 * For extra safety, call stc_init after g_thread_init, if present.
 * Currently we just call srand(), but since we use GLib, we may need
 * to add some Glib stuff here and that must come after g_thread_init.
 */
void stc_init(void)
{
	srand(time(NULL) ^ getpid());	// for cld_rand64 et.al.
}



#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <libxml/tree.h>
#include <glib.h>
#include <chunkc.h>
#include <netdb.h>
#include <chunk_msg.h>
#include <chunksrv.h>

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

static bool net_read(struct st_client *stc, void *data, size_t datalen)
{
	if (!datalen)
		return true;

	if (stc->ssl) {
		int rc;

		while (datalen) {
			rc = SSL_read(stc->ssl, data, datalen);
			if (rc < 0)
				return false;
			datalen -= rc;
			data += rc;
		}
	} else {
		ssize_t rc;

		while (datalen) {
			rc = read(stc->fd, data, datalen);
			if (rc < 0)
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

struct st_client *stc_new(const char *service_host, int port,
			  const char *user, const char *secret_key,
			  bool encrypt)
{
	struct st_client *stc;
	struct addrinfo hints, *res = NULL, *rp;
	int rc, fd = -1, on = 1;
	char port_str[32];

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

	if (encrypt) {
		stc->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		if (!stc->ssl_ctx)
			goto err_out;

		SSL_CTX_set_mode(stc->ssl_ctx, SSL_MODE_AUTO_RETRY);

		stc->ssl = SSL_new(stc->ssl_ctx);
		if (!stc->ssl)
			goto err_out_ctx;

		if (!SSL_set_fd(stc->ssl, stc->fd))
			goto err_out_ssl;

		if (SSL_connect(stc->ssl) <= 0)
			goto err_out_ssl;
	}

	return stc;

err_out_ssl:
	SSL_free(stc->ssl);
err_out_ctx:
	SSL_CTX_free(stc->ssl_ctx);
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

bool stc_get(struct st_client *stc, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers)
{
	char netbuf[4096];
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;
	uint64_t content_len;

	if (stc->verbose)
		fprintf(stderr, "libstc: GET(%s)\n", key);

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_GET;
	req.nonce = rand();
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	/* sign request */
	chreq_sign(&req, stc->key, req.checksum);

	/* write request */
	if (!net_write(stc, &req, sizeof(req)))
		return false;

	/* read response header */
	if (!net_read(stc, &resp, sizeof(resp.req)))
		return false;

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "GET resp code: %d\n", resp.req.resp_code);
		return false;
	}

	/* read rest of response header */
	if (!net_read(stc, &resp.mtime, sizeof(resp) - sizeof(resp.req)))
		return false;

	content_len = GUINT64_FROM_LE(resp.req.data_len);

	/* read response data */
	while (content_len) {
		int xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		if (!net_read(stc, netbuf, xfer_len))
			return false;

		write_cb(netbuf, xfer_len, 1, user_data);
		content_len -= xfer_len;
	}

	return true;
}

void *stc_get_inline(struct st_client *stc, const char *key,
		     bool want_headers, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = stc_get(stc, key, all_data_cb, all_data, want_headers);
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

bool stc_put(struct st_client *stc, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data)
{
	GByteArray *all_data;
	char netbuf[4096];
	struct chunksrv_req req;
	struct chunksrv_req resp;
	uint64_t content_len = len;

	if (stc->verbose)
		fprintf(stderr, "libstc: PUT(%s, %Lu)\n", key,
			(unsigned long long) len);

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_PUT;
	req.nonce = rand();
	req.data_len = GUINT64_TO_LE(content_len);
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	all_data = g_byte_array_new();
	if (!all_data)
		return false;

	/* sign request */
	chreq_sign(&req, stc->key, req.checksum);

	/* write request */
	if (!net_write(stc, &req, sizeof(req)))
		goto err_out;

	while (content_len) {
		size_t rrc;
		int xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		rrc = read_cb(netbuf, xfer_len, 1, user_data);
		if (rrc < 1)
			goto err_out;

		content_len -= rrc;

		if (!net_write(stc, netbuf, rrc))
			goto err_out;
	}

	/* read response header */
	if (!net_read(stc, &resp, sizeof(resp)))
		goto err_out;

	/* check response code */
	if (resp.resp_code != Success) {
		fprintf(stderr, "PUT resp code: %d\n", resp.resp_code);
		goto err_out;
	}

	g_byte_array_free(all_data, TRUE);
	return true;

err_out:
	g_byte_array_free(all_data, TRUE);
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
	int len = size * nmemb;

	len = MIN(len, spi->len);
	if (len) {
		memcpy(ptr, spi->data, len);
		spi->data += len;
		spi->len -= len;
	}

	return len;
}

bool stc_put_inline(struct st_client *stc, const char *key,
	     void *data, uint64_t len)
{
	struct stc_put_info spi = { data, len };

	return stc_put(stc, key, read_inline_cb, len, &spi);
}

bool stc_del(struct st_client *stc, const char *key)
{
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;

	if (stc->verbose)
		fprintf(stderr, "libstc: DEL(%s)\n", key);

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_DEL;
	req.nonce = rand();
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	/* sign request */
	chreq_sign(&req, stc->key, req.checksum);

	/* write request */
	if (!net_write(stc, &req, sizeof(req)))
		return false;

	/* read response header */
	if (!net_read(stc, &resp, sizeof(resp.req)))
		return false;

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "DEL resp code: %d\n", resp.req.resp_code);
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
	struct st_object *obj = calloc(1, sizeof(*obj));
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
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;
	uint64_t content_len;

	if (stc->verbose)
		fprintf(stderr, "libstc: LIST-KEYS\n");

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_LIST;
	req.nonce = rand();
	strcpy(req.user, stc->user);

	/* sign request */
	chreq_sign(&req, stc->key, req.checksum);

	/* write request */
	if (!net_write(stc, &req, sizeof(req)))
		return false;

	/* read response header */
	if (!net_read(stc, &resp, sizeof(resp.req)))
		return false;

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "LIST resp code: %d\n", resp.req.resp_code);
		return false;
	}

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	content_len = GUINT64_FROM_LE(resp.req.data_len);

	/* read response data */
	while (content_len) {
		int xfer_len;

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
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;

	if (stc->verbose)
		fprintf(stderr, "libstc: PING\n");

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_NOP;
	req.nonce = rand();
	strcpy(req.user, stc->user);

	/* sign request */
	chreq_sign(&req, stc->key, req.checksum);

	/* write request */
	if (!net_write(stc, &req, sizeof(req)))
		return false;

	/* read response header */
	if (!net_read(stc, &resp, sizeof(resp.req)))
		return false;

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "NOP resp code: %d\n", resp.req.resp_code);
		return false;
	}

	return true;
}


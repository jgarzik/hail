
#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/hmac.h>
#include <libxml/tree.h>
#include <glib.h>
#include <stc.h>
#include <netdb.h>
#include <chunk_msg.h>

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

void stc_free(struct st_client *stc)
{
	if (!stc)
		return;

	if (stc->fd >= 0)
		close(stc->fd);
	free(stc->host);
	free(stc->user);
	free(stc->key);
	free(stc);
}

struct st_client *stc_new(const char *service_host, int port,
			  const char *user, const char *secret_key,
			  bool encrypt)
{
	struct st_client *stc;
	struct addrinfo hints, *res = NULL, *rp;
	int rc, fd;
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

		perror("connect");
		close(fd);
	}

	freeaddrinfo(res);

	if (!rp)
		return NULL;

	stc = calloc(1, sizeof(struct st_client));
	if (!stc)
		return NULL;

	stc->fd = fd;
	stc->ssl = encrypt;
	stc->host = strdup(service_host);
	stc->user = strdup(user);
	stc->key = strdup(secret_key);

	if (!stc->host || !stc->user || !stc->key)
		goto err_out;

	return stc;

err_out:
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
	ssize_t xrc;
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;
	uint64_t content_len;

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_GET;
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	/* write request */
	xrc = write(stc->fd, &req, sizeof(req));
	if (xrc != sizeof(req)) {
		perror("write req");
		return false;
	}

	/* read response header */
	xrc = read(stc->fd, &resp, sizeof(resp.req));
	if (xrc != sizeof(resp.req)) {
		perror("read hdr");
		return false;
	}

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "get resp code: %d\n", resp.req.resp_code);
		return false;
	}

	/* read rest of response header */
	xrc = read(stc->fd, &resp.mtime, sizeof(resp) - sizeof(resp.req));
	if (xrc != (sizeof(resp) - sizeof(resp.req))) {
		perror("read rest");
		return false;
	}

	content_len = GUINT64_FROM_LE(resp.req.data_len);

	/* read response data */
	while (content_len) {
		int xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		xrc = read(stc->fd, netbuf, xfer_len);
		if (xrc != xfer_len) {
			perror("read netbuf");
			return false;
		}

		write_cb(netbuf, xrc, 1, user_data);
		content_len -= xrc;
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
	ssize_t xrc;
	struct chunksrv_req req;
	struct chunksrv_req resp;
	uint64_t content_len = len;

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_PUT;
	req.data_len = GUINT64_TO_LE(content_len);
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	all_data = g_byte_array_new();
	if (!all_data)
		return false;

	/* write request */
	xrc = write(stc->fd, &req, sizeof(req));
	if (xrc != sizeof(req)) {
		perror("write req");
		goto err_out;
	}

	while (content_len) {
		size_t rrc;
		int xfer_len;

		xfer_len = MIN(content_len, sizeof(netbuf));
		rrc = read_cb(netbuf, xfer_len, 1, user_data);
		if (rrc < 1)
			goto err_out;

		content_len -= rrc;

		xrc = write(stc->fd, netbuf, rrc);
		if (xrc != rrc) {
			perror("write netbuf");
			goto err_out;
		}
	}

	/* read response header */
	xrc = read(stc->fd, &resp, sizeof(resp));
	if (xrc != sizeof(resp)) {
		perror("read hdr");
		goto err_out;
	}

	/* check response code */
	if (resp.resp_code != Success) {
		fprintf(stderr, "put resp code: %d\n", resp.resp_code);
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
	ssize_t xrc;
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_DEL;
	strcpy(req.user, stc->user);
	strcpy(req.key, key);

	/* write request */
	xrc = write(stc->fd, &req, sizeof(req));
	if (xrc != sizeof(req)) {
		perror("write req");
		return false;
	}

	/* read response header */
	xrc = read(stc->fd, &resp, sizeof(resp.req));
	if (xrc != sizeof(resp.req)) {
		perror("read hdr");
		return false;
	}

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "del resp code: %d\n", resp.req.resp_code);
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
	ssize_t xrc;
	struct chunksrv_req req;
	struct chunksrv_resp_get resp;
	uint64_t content_len;

	/* initialize request */
	memset(&req, 0, sizeof(req));
	memcpy(req.magic, CHUNKD_MAGIC, CHD_MAGIC_SZ);
	req.op = CHO_LIST;
	strcpy(req.user, stc->user);

	/* write request */
	xrc = write(stc->fd, &req, sizeof(req));
	if (xrc != sizeof(req)) {
		perror("write req");
		return false;
	}

	/* read response header */
	xrc = read(stc->fd, &resp, sizeof(resp.req));
	if (xrc != sizeof(resp.req)) {
		perror("read hdr");
		return false;
	}

	/* check response code */
	if (resp.req.resp_code != Success) {
		fprintf(stderr, "get resp code: %d\n", resp.req.resp_code);
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
		xrc = read(stc->fd, netbuf, xfer_len);
		if (xrc != xfer_len) {
			perror("read netbuf");
			goto err_out;
		}

		g_byte_array_append(all_data, (unsigned char *)netbuf, xrc);
		content_len -= xrc;
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


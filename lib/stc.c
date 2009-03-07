
#define _GNU_SOURCE
#include "storaged-config.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <libxml/tree.h>
#include <glib.h>
#include <stc.h>
#include <httputil.h>
#include <pcre.h>

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
	if (stc->curl)
		curl_easy_cleanup(stc->curl);
	free(stc->host);
	free(stc->user);
	free(stc->key);
	free(stc->url);
	free(stc);

	curl_global_cleanup();
}

struct st_client *stc_new(const char *service_host, int port,
			  const char *user, const char *secret_key,
			  bool encrypt)
{
	struct st_client *stc;

	stc = calloc(1, sizeof(struct st_client));
	if (!stc)
		return NULL;

	stc->ssl = encrypt;
	stc->host = strdup(service_host);
	stc->user = strdup(user);
	stc->key = strdup(secret_key);

	asprintf(&stc->url, "http%s://%s:%d",
		 encrypt ? "s" : "",
		 service_host,
		 port);

	if (!stc->host || !stc->user || !stc->key || !stc->url)
		goto err_out;

	if (curl_global_init(CURL_GLOBAL_ALL))
		goto err_out;

	stc->curl = curl_easy_init();
	if (!stc->curl)
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

bool stc_get(struct st_client *stc, const char *volume, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;

	if (asprintf(&stmp, "/%s/%s", volume, key) < 0)
		return false;

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, stc->key, hmac);

	sprintf(auth, "Authorization: STOR %s:%s", stc->user, hmac);
	sprintf(host, "Host: %s", stc->host);
	sprintf(url, "%s%s", stc->url, orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(stc->curl);
	if (stc->verbose)
		curl_easy_setopt(stc->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(stc->curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(stc->curl, CURLOPT_URL, url);
	curl_easy_setopt(stc->curl, CURLOPT_HEADER, want_headers ? 1 : 0);
	curl_easy_setopt(stc->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(stc->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(stc->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEDATA, user_data);

	rc = curl_easy_perform(stc->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

void *stc_get_inline(struct st_client *stc, const char *volume, const char *key,
		     bool want_headers, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = stc_get(stc, volume, key, all_data_cb, all_data, want_headers);
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

bool stc_put(struct st_client *stc, const char *volume,
	     const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80];
	char url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;
	GByteArray *all_data;

	if (asprintf(&stmp, "/%s/%s", volume, key) < 0)
		return false;

	all_data = g_byte_array_new();
	if (!all_data) {
		free(stmp);
		return false;
	}

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "PUT";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, stc->key, hmac);

	sprintf(auth, "Authorization: STOR %s:%s", stc->user, hmac);
	sprintf(host, "Host: %s", stc->host);
	sprintf(url, "%s%s", stc->url, orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(stc->curl);
	if (stc->verbose)
		curl_easy_setopt(stc->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(stc->curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(stc->curl, CURLOPT_URL, url);
	curl_easy_setopt(stc->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(stc->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(stc->curl, CURLOPT_READFUNCTION, read_cb);
	curl_easy_setopt(stc->curl, CURLOPT_READDATA, user_data);
	curl_easy_setopt(stc->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEDATA, all_data);
	curl_easy_setopt(stc->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(stc->curl, CURLOPT_HEADER, 1);
	curl_easy_setopt(stc->curl, CURLOPT_INFILESIZE_LARGE, len);

	rc = curl_easy_perform(stc->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	if (rc)
		goto err_out;

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

bool stc_put_inline(struct st_client *stc, const char *volume,
	     const char *key,
	     void *data, uint64_t len)
{
	struct stc_put_info spi = { data, len };

	return stc_put(stc, volume, key, read_inline_cb, len, &spi);
}

bool stc_del(struct st_client *stc, const char *volume, const char *key)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;

	if (asprintf(&stmp, "/%s/%s", volume, key) < 0)
		return false;

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "DELETE";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, stc->key, hmac);

	sprintf(auth, "Authorization: STOR %s:%s", stc->user, hmac);
	sprintf(host, "Host: %s", stc->host);
	sprintf(url, "%s%s", stc->url, orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(stc->curl);
	if (stc->verbose)
		curl_easy_setopt(stc->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(stc->curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(stc->curl, CURLOPT_URL, url);
	curl_easy_setopt(stc->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(stc->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(stc->curl, CURLOPT_CUSTOMREQUEST, req.method);

	rc = curl_easy_perform(stc->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

void stc_free_volume(struct st_volume *vol)
{
	if (!vol)
		return;

	free(vol->name);
	free(vol);
}

void stc_free_vlist(struct st_vlist *vlist)
{
	GList *tmp;

	if (!vlist)
		return;

	free(vlist->owner);

	tmp = vlist->list;
	while (tmp) {
		struct st_volume *vol;

		vol = tmp->data;
		stc_free_volume(vol);

		tmp = tmp->next;
	}

	g_list_free(vlist->list);

	free(vlist);
}

static void stc_parse_volumes(xmlDocPtr doc, xmlNode *node,
			      struct st_vlist *vlist)
{
	struct st_volume *vol;
	xmlNode *tmp;

	while (node) {
		if (node->type != XML_ELEMENT_NODE)
			goto next;

		if (_strcmp(node->name, "Volume"))
			goto next;

		vol = calloc(1, sizeof(*vol));
		if (!vol)
			goto next;

		tmp = node->children;
		while (tmp) {
			if (tmp->type != XML_ELEMENT_NODE)
				goto next_tmp;

			if (!_strcmp(tmp->name, "Name"))
				vol->name = (char *) xmlNodeListGetString(doc,
							tmp->children, 1);

next_tmp:
			tmp = tmp->next;
		}

		if (!vol->name)
			stc_free_volume(vol);
		else
			vlist->list = g_list_append(vlist->list, vol);

next:
		node = node->next;
	}
}

struct st_vlist *stc_list_volumes(struct st_client *stc)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80], url[80];
	struct curl_slist *headers = NULL;
	struct st_vlist *vlist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	int rc;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = "/";

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, stc->key, hmac);

	sprintf(auth, "Authorization: STOR %s:%s", stc->user, hmac);
	sprintf(host, "Host: %s", stc->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	sprintf(url, "%s/", stc->url);

	curl_easy_reset(stc->curl);
	if (stc->verbose)
		curl_easy_setopt(stc->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(stc->curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(stc->curl, CURLOPT_URL, url);
	curl_easy_setopt(stc->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(stc->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(stc->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEDATA, all_data);

	rc = curl_easy_perform(stc->curl);

	curl_slist_free_all(headers);

	if (rc)
		goto err_out;

	doc = xmlReadMemory((char *) all_data->data, all_data->len,
			    "foo.xml", NULL, 0);
	if (!doc)
		goto err_out;

	node = xmlDocGetRootElement(doc);
	if (!node)
		goto err_out_doc;

	if (_strcmp(node->name, "ListAllMyVolumesResult"))
		goto err_out_doc;

	vlist = calloc(1, sizeof(*vlist));
	if (!vlist)
		goto err_out_doc;

	node = node->children;
	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Owner")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			vlist->owner = strdup((char *)xs);
			xmlFree(xs);
		}

		else if (!_strcmp(node->name, "Volumes"))
			stc_parse_volumes(doc, node->children, vlist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;

	return vlist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;
	return NULL;
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

struct st_keylist *stc_keys(struct st_client *stc, const char *volume)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80];
	char orig_path[strlen(volume) + 8];
	struct curl_slist *headers = NULL;
	struct st_keylist *keylist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	GString *url;
	int rc;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	sprintf(orig_path, "/%s/", volume);

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, stc->key, hmac);

	sprintf(auth, "Authorization: STOR %s:%s", stc->user, hmac);
	sprintf(host, "Host: %s", stc->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	url = g_string_sized_new(256);
	if (!url) {
		curl_slist_free_all(headers);
		goto err_out;
	}

	url = g_string_append(url, stc->url);
	url = g_string_append(url, orig_path);

	curl_easy_reset(stc->curl);
	if (stc->verbose)
		curl_easy_setopt(stc->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(stc->curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(stc->curl, CURLOPT_URL, url->str);
	curl_easy_setopt(stc->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(stc->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(stc->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(stc->curl, CURLOPT_WRITEDATA, all_data);

	rc = curl_easy_perform(stc->curl);

	g_string_free(url, TRUE);
	curl_slist_free_all(headers);

	if (rc)
		goto err_out;

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


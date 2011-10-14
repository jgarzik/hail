
/*
 * Copyright 2008-2010 Red Hat, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <libxml/tree.h>
#include <glib.h>
#include <hstor.h>

static int _strcasecmp(const unsigned char *a, const char *b)
{
	return xmlStrcasecmp(a, (const unsigned char *) b);
}

static int _strcmp(const unsigned char *a, const char *b)
{
	return xmlStrcmp(a, (const unsigned char *) b);
}

void hstor_free(struct hstor_client *hstor)
{
	if (hstor->curl)
		curl_easy_cleanup(hstor->curl);
	free(hstor->acc);
	free(hstor->host);
	free(hstor->user);
	free(hstor->key);
	free(hstor);
}

/*
 * The service accessor is a "host:port" string that gets resolved to IP
 * address and then create a TCP connection to the server. The service host,
 * however, is used to form the "Host: host" HTTP header. The host of the
 * accessor should be the same on the sane installations, but whatever.
 */
struct hstor_client *hstor_new(const char *service_acc,
	const char *service_host, const char *user, const char *secret_key)
{
	struct hstor_client *hstor;

	hstor = calloc(1, sizeof(struct hstor_client));
	if (!hstor)
		return NULL;

	hstor->acc = strdup(service_acc);
	hstor->host = strdup(service_host);
	hstor->user = strdup(user);
	hstor->key = strdup(secret_key);
	if (!hstor->acc || !hstor->host || !hstor->user || !hstor->key)
		goto err_out;

	if (curl_global_init(CURL_GLOBAL_ALL))
		goto err_out;

	hstor->curl = curl_easy_init();
	if (!hstor->curl)
		goto err_out;

	return hstor;

err_out:
	hstor_free(hstor);
	return NULL;
}

bool hstor_set_format(struct hstor_client *hstor, enum hstor_calling_format f)
{
	switch (f) {
	case HFMT_ORDINARY:
		hstor->subdomain = false;
		break;
	case HFMT_SUBDOMAIN:
		hstor->subdomain = true;
		break;
	default:
		return false;
	}
	return true;
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	GByteArray *all_data = user_data;
	int len = size * nmemb;

	g_byte_array_append(all_data, ptr, len);

	return len;
}

void hstor_free_bucket(struct hstor_bucket *buck)
{
	if (!buck)
		return;

	free(buck->name);
	free(buck->time_create);
	free(buck);
}

void hstor_free_blist(struct hstor_blist *blist)
{
	GList *tmp;

	if (!blist)
		return;

	free(blist->own_id);
	free(blist->own_name);

	tmp = blist->list;
	while (tmp) {
		struct hstor_bucket *buck;

		buck = tmp->data;
		hstor_free_bucket(buck);

		tmp = tmp->next;
	}

	g_list_free(blist->list);

	free(blist);
}

static void hstor_parse_buckets(xmlDocPtr doc, xmlNode *node,
			      struct hstor_blist *blist)
{
	struct hstor_bucket *buck;
	xmlNode *tmp;

	while (node) {
		if (node->type != XML_ELEMENT_NODE)
			goto next;

		if (_strcmp(node->name, "Bucket"))
			goto next;

		buck = calloc(1, sizeof(*buck));
		if (!buck)
			goto next;

		tmp = node->children;
		while (tmp) {
			if (tmp->type != XML_ELEMENT_NODE)
				goto next_tmp;

			if (!_strcmp(tmp->name, "Name"))
				buck->name = (char *) xmlNodeListGetString(doc,
							tmp->children, 1);

			else if (!_strcmp(tmp->name, "CreationDate"))
				buck->time_create = (char *)
					xmlNodeListGetString(doc,
							     tmp->children, 1);

next_tmp:
			tmp = tmp->next;
		}

		if (!buck->name)
			hstor_free_bucket(buck);
		else
			blist->list = g_list_append(blist->list, buck);

next:
		node = node->next;
	}
}

static bool hstor_resplit(const struct hstor_client *hstor,
			  const char *bucket, const char *key,
			  char **url, char **hosthdr, char **path)
{
	char *unesc_path;
	int rc;

	if (hstor->subdomain)
		rc = asprintf(&unesc_path, "/%s", key);
	else
		rc = asprintf(&unesc_path, "/%s/%s", bucket, key);
	if (rc < 0)
		goto err_spath;
	*path = huri_field_escape(unesc_path, PATH_ESCAPE_MASK);
	if (!*path)
		goto err_epath;

	if (hstor->subdomain)
		rc = asprintf(hosthdr, "Host: %s.%s", bucket, hstor->host);
	else
		rc = asprintf(hosthdr, "Host: %s", hstor->host);
	if (rc < 0)
		goto err_host;

	if (hstor->subdomain)
		rc = asprintf(url, "http://%s.%s%s", bucket, hstor->acc, *path);
	else
		rc = asprintf(url, "http://%s%s", hstor->acc, *path);
	if (rc < 0)
		goto err_url;

	free(unesc_path);
	return true;

	/* free(*url); */
 err_url:
	free(*hosthdr);
 err_host:
	free(*path);
 err_epath:
	free(unesc_path);
 err_spath:
	return false;
}

struct hstor_blist *hstor_list_buckets(struct hstor_client *hstor)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *host, *url;
	struct curl_slist *headers = NULL;
	struct hstor_blist *blist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	int rc;

	all_data = g_byte_array_new();
	if (!all_data)
		goto err_data;

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = "/";

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	hreq_sign(&req, NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);
	if (asprintf(&host, "Host: %s", hstor->host) < 0)
		goto err_host;
	if (asprintf(&url, "http://%s/", hstor->acc) < 0)
		goto err_url;

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEDATA, all_data);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

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

	if (_strcmp(node->name, "ListAllMyBucketsResult"))
		goto err_out_doc;

	blist = calloc(1, sizeof(*blist));
	if (!blist)
		goto err_out_doc;

	node = node->children;
	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Owner")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "ID")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					blist->own_id = strdup((char *)xs);
					xmlFree(xs);
				}

				else if (!_strcmp(tmp->name, "DisplayName")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					blist->own_name = strdup((char *)xs);
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}

		else if (!_strcmp(node->name, "Buckets"))
			hstor_parse_buckets(doc, node->children, blist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	g_byte_array_free(all_data, TRUE);
	free(url);
	free(host);

	return blist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	free(url);
err_url:
	free(host);
err_host:
	g_byte_array_free(all_data, TRUE);
err_data:
	return NULL;
}

static bool __hstor_ad_bucket(struct hstor_client *hstor, const char *name,
			    bool delete)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *host, *url, *orig_path;
	struct curl_slist *headers = NULL;
	int rc;

	if (!hstor_resplit(hstor, name, "", &url, &host, &orig_path))
		goto err_split;

	memset(&req, 0, sizeof(req));
	req.method = delete ? "DELETE" : "PUT";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	hreq_sign(&req, hstor->subdomain ? name : NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

	curl_slist_free_all(headers);

	free(url);
	free(host);
	free(orig_path);
	return (rc == 0);

err_split:
	return false;
}

bool hstor_add_bucket(struct hstor_client *hstor, const char *name)
{
	return __hstor_ad_bucket(hstor, name, false);
}

bool hstor_del_bucket(struct hstor_client *hstor, const char *name)
{
	return __hstor_ad_bucket(hstor, name, true);
}

bool hstor_get(struct hstor_client *hstor, const char *bucket, const char *key,
	     size_t (*write_cb)(const void *, size_t, size_t, void *),
	     void *user_data, bool want_headers)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *url, *host, *orig_path;
	struct curl_slist *headers = NULL;
	int rc;

	if (!hstor_resplit(hstor, bucket, key, &url, &host, &orig_path))
		goto err_split;

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	hreq_sign(&req, hstor->subdomain ? bucket : NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(hstor->curl, CURLOPT_HEADER, want_headers ? 1 : 0);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEDATA, user_data);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

	curl_slist_free_all(headers);
	free(url);
	free(host);
	free(orig_path);
	return (rc == 0);

err_split:
	return false;
}

void *hstor_get_inline(struct hstor_client *hstor, const char *bucket, const char *key,
		     bool want_headers, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = hstor_get(hstor, bucket, key, all_data_cb, all_data, want_headers);
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

bool hstor_put(struct hstor_client *hstor, const char *bucket, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char **user_hdrs)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *host, *url, *orig_path;
	char *uhdr_buf = NULL;
	struct curl_slist *headers = NULL;
	int rc = -1;

	if (!hstor_resplit(hstor, bucket, key, &url, &host, &orig_path))
		goto err_split;

	memset(&req, 0, sizeof(req));
	req.method = "PUT";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	if (user_hdrs) {
		int idx = 0;
		size_t uhdr_len = 0, ukey_len;
		void *p;
		char *colon, *ukey, *uval;

		/* 1. add to curl hdr list.  2. count hdr byte size */
		while (user_hdrs[idx]) {
			headers = curl_slist_append(headers, user_hdrs[idx]);
			uhdr_len += strlen(user_hdrs[idx]) + 2;
			idx++;
		}

		/* alloc buf to hold all hdr strings */
		uhdr_buf = calloc(1, uhdr_len);
		if (!uhdr_buf)
			goto err_ubuf;

		/* copy and nul-terminate hdr keys and values for signing */
		idx = 0;
		p = uhdr_buf;
		while (user_hdrs[idx]) {
			ukey = p;
			colon = strchr(user_hdrs[idx], ':');
			if (colon) {
				ukey_len = colon - user_hdrs[idx];
				memcpy(ukey, user_hdrs[idx], ukey_len);
				ukey[ukey_len] = 0;

				p += ukey_len + 1;

				colon++;
				while (*colon && isspace(*colon))
					colon++;

				uval = p;
				strcpy(uval, colon);
				p += strlen(uval) + 1;

				hreq_hdr_push(&req, ukey, uval);
			}
			idx++;
		}
	}

	hreq_sign(&req, hstor->subdomain ? bucket : NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_READFUNCTION, read_cb);
	curl_easy_setopt(hstor->curl, CURLOPT_READDATA, user_data);
	curl_easy_setopt(hstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(hstor->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_INFILESIZE_LARGE,
			 (curl_off_t)len);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

	curl_slist_free_all(headers);
	free(url);
	free(host);
	free(orig_path);
	free(uhdr_buf);
	return (rc == 0);

	/* free(uhdr_buf); */
err_ubuf:
	free(url);
	free(host);
	free(orig_path);
err_split:
	return false;
}

struct hstor_put_info {
	void		*data;
	uint64_t	len;
};

static size_t read_inline_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct hstor_put_info *spi = user_data;
	int len = size * nmemb;

	len = MIN(len, spi->len);
	if (len) {
		memcpy(ptr, spi->data, len);
		spi->data += len;
		spi->len -= len;
	}

	return len;
}

bool hstor_put_inline(struct hstor_client *hstor, const char *bucket, const char *key,
	     void *data, uint64_t len, char **user_hdrs)
{
	struct hstor_put_info spi = { data, len };

	return hstor_put(hstor, bucket, key, read_inline_cb, len, &spi, user_hdrs);
}

bool hstor_del(struct hstor_client *hstor, const char *bucket, const char *key)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *host, *url, *orig_path;
	struct curl_slist *headers = NULL;
	int rc;

	if (!hstor_resplit(hstor, bucket, key, &url, &host, &orig_path))
		goto err_split;

	memset(&req, 0, sizeof(req));
	req.method = "DELETE";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	hreq_sign(&req, NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

	curl_slist_free_all(headers);
	free(url);
	free(host);
	free(orig_path);
	return (rc == 0);

err_split:
	return false;
}

static GString *append_qparam(GString *str, const char *key, const char *val,
		       char *arg_char)
{
	char *stmp;

	str = g_string_append(str, arg_char);
	arg_char[0] = '&';

	str = g_string_append(str, key);
	str = g_string_append(str, "=");

	stmp = huri_field_escape(val, QUERY_ESCAPE_MASK);
	if (stmp) {
		str = g_string_append(str, stmp);
		free(stmp);
	}

	return str;
}

void hstor_free_object(struct hstor_object *obj)
{
	if (!obj)
		return;

	free(obj->key);
	free(obj->time_mod);
	free(obj->etag);
	free(obj->storage);
	free(obj->own_id);
	free(obj->own_name);
	free(obj);
}

void hstor_free_keylist(struct hstor_keylist *keylist)
{
	GList *tmp;

	if (!keylist)
		return;

	free(keylist->name);
	free(keylist->prefix);
	free(keylist->marker);
	free(keylist->delim);

	tmp = keylist->common_pfx;
	while (tmp) {
		free(tmp->data);
		tmp = tmp->next;
	}

	tmp = keylist->contents;
	while (tmp) {
		hstor_free_object(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(keylist->contents);

	free(keylist);
}

static void hstor_parse_key(xmlDocPtr doc, xmlNode *node,
			  struct hstor_keylist *keylist)
{
	struct hstor_object *obj;
	xmlChar *xs;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return;

	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Key")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->key = strdup((char *)xs);
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
		else if (!_strcmp(node->name, "StorageClass")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->storage = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Owner")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "ID")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					obj->own_id = strdup((char *)xs);
					xmlFree(xs);
				}

				else if (!_strcmp(tmp->name, "DisplayName")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					obj->own_name = strdup((char *)xs);
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}

		node = node->next;
	}

	if (obj->key)
		keylist->contents = g_list_append(keylist->contents, obj);
	else
		hstor_free_object(obj);
}

struct hstor_keylist *hstor_keys(struct hstor_client *hstor, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128];
	char *host, *orig_path;
	struct curl_slist *headers = NULL;
	struct hstor_keylist *keylist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	GString *url;
	int rc;
	char arg_char[2] = "?";

	all_data = g_byte_array_new();
	if (!all_data)
		goto err_data;

	if (hstor->subdomain) {
		if (asprintf(&orig_path, "/") < 0)
			goto err_spath;
	} else {
		if (asprintf(&orig_path, "/%s/", bucket) < 0)
			goto err_spath;
	}

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s",
		hutil_time2str(timestr, sizeof(timestr), time(NULL)));

	hreq_hdr_push(&req, "Date", timestr);

	hreq_sign(&req, hstor->subdomain? bucket: NULL, hstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", hstor->user, hmac);
	if (hstor->subdomain) {
		if (asprintf(&host, "Host: %s.%s", bucket, hstor->host) < 0)
			goto err_host;
	} else {
		if (asprintf(&host, "Host: %s", hstor->host) < 0)
			goto err_host;
	}

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	url = g_string_sized_new(256);
	if (!url) {
		curl_slist_free_all(headers);
		goto err_out;
	}

	url = g_string_append(url, "http://");
	if (hstor->subdomain) {
		url = g_string_append(url, bucket);
		url = g_string_append(url, ".");
	}
	url = g_string_append(url, hstor->acc);
	url = g_string_append(url, orig_path);

	if (prefix)
		url = append_qparam(url, "prefix", prefix, arg_char);
	if (marker)
		url = append_qparam(url, "marker", marker, arg_char);
	if (delim)
		url = append_qparam(url, "delimiter", delim, arg_char);
	if (max_keys) {
		char mk[32];
		sprintf(mk, "%smax-keys=%u", arg_char, max_keys);
		url = g_string_append(url, mk);
	}

	curl_easy_reset(hstor->curl);
	if (hstor->verbose)
		curl_easy_setopt(hstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_URL, url->str);
	curl_easy_setopt(hstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(hstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(hstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(hstor->curl, CURLOPT_WRITEDATA, all_data);
	curl_easy_setopt(hstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(hstor->curl);

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

	if (_strcmp(node->name, "ListBucketResult"))
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
		else if (!_strcmp(node->name, "Prefix")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->prefix = strdup(xs? (char *)xs: "");
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Marker")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->marker = strdup(xs ? (char *)xs : "");
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Delimiter")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->delim = strdup(xs ? (char *)xs : "");
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "MaxKeys")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->max_keys = (unsigned int) atoi((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "IsTruncated")) {
			xs = xmlNodeListGetString(doc, node->children, 1);

			if (!_strcasecmp(xs, "true"))
				keylist->trunc = true;
			else if (!_strcasecmp(xs, "1"))
				keylist->trunc = true;
			else
				keylist->trunc = false;

			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "CommonPrefixes")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "Prefix")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					keylist->common_pfx =
						g_list_append(
							keylist->common_pfx,
							strdup((char *)xs));
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}
		else if (!_strcmp(node->name, "Contents"))
			hstor_parse_key(doc, node->children, keylist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	free(host);
	free(orig_path);
	g_byte_array_free(all_data, TRUE);

	return keylist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	free(host);
err_host:
	free(orig_path);
err_spath:
	g_byte_array_free(all_data, TRUE);
err_data:
	return NULL;
}


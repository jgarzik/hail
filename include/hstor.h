#ifndef __HSTOR_H__
#define __HSTOR_H__

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


#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#include <glib.h>

struct hstor_client {
	CURL		*curl;
	char		*acc;
	char		*host;
	char		*user;
	char		*key;
	bool		verbose;
};

struct hstor_bucket {
	char		*name;
	char		*time_create;
};

struct hstor_blist {
	char		*own_id;	/* ID */
	char		*own_name;	/* DisplayName */
	GList		*list;		/* list of hstor_bucket */
};

struct hstor_object {
	char		*key;
	char		*time_mod;
	char		*etag;
	uint64_t	size;
	char		*storage;
	char		*own_id;
	char		*own_name;
};

struct hstor_keylist {
	char		*name;
	char		*prefix;
	char		*marker;
	char		*delim;
	unsigned int	max_keys;
	bool		trunc;
	GList		*contents;
	GList		*common_pfx;
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define PATH_ESCAPE_MASK        0x02
#define QUERY_ESCAPE_MASK       0x04

enum {
	HREQ_MAX_HDR		= 128,		/* max hdrs per req */
};

struct http_uri {
	char		*scheme;
	unsigned int	scheme_len;
	char		*userinfo;
	unsigned int	userinfo_len;
	char		*hostname;
	unsigned int	hostname_len;

	unsigned int	port;

	char		*path;
	unsigned int	path_len;
	char		*query;
	unsigned int	query_len;
	char		*fragment;
	unsigned int	fragment_len;	/* see FIXME in uri.c */
};


struct http_hdr {
	char			*key;
	char			*val;
};

struct http_req {
	char			*method;	/* GET, POST, etc. */
	struct http_uri		uri;		/* URI */
	int			major;		/* HTTP version */
	int			minor;

	char			*orig_path;

	unsigned int		n_hdr;		/* list of headers */
	struct http_hdr		hdr[HREQ_MAX_HDR];
};

enum ReqQ {
	URIQ_ACL,
	URIQ_LOCATION,
	URIQ_LOGGING,
	URIQ_TORRENT,
	URIQNUM
};

enum ReqACLC {
	ACLC_PRIV,
	ACLC_PUB_R,
	ACLC_PUB_RW,
	ACLC_AUTH_R,
	ACLCNUM
};

/* hutil.c */
extern char *hutil_time2str(char *buf, int len, time_t time);
extern time_t hutil_str2time(const char *timestr);
extern int hreq_hdr_push(struct http_req *req, const char *key, const char *val);
extern char *hreq_hdr(struct http_req *req, const char *key);
extern void hreq_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);
extern GHashTable *hreq_query(struct http_req *req);
extern int hreq_is_query(struct http_req *req);
extern void hreq_free(struct http_req *req);
extern int hreq_acl_canned(struct http_req *req);

/* uri.c */
extern struct http_uri *huri_parse(struct http_uri *uri_dest, char *uri_src_text);
extern int huri_field_unescape(char *s, int s_len);
extern char* huri_field_escape(const char *signed_str, unsigned char mask);

static inline bool hreq_http11(struct http_req *req)
{
	if (req->major > 1)
		return true;
	if (req->major == 1 && req->minor > 0)
		return true;
	return false;
}

/* hstor.c */
extern void hstor_free(struct hstor_client *hstor);
extern void hstor_free_blist(struct hstor_blist *blist);
extern void hstor_free_bucket(struct hstor_bucket *buck);
extern void hstor_free_object(struct hstor_object *obj);
extern void hstor_free_keylist(struct hstor_keylist *keylist);

extern struct hstor_client *hstor_new(const char *service_acc,
	const char *service_host, const char *user, const char *secret_key);

extern bool hstor_add_bucket(struct hstor_client *hstor, const char *name);
extern bool hstor_del_bucket(struct hstor_client *hstor, const char *name);

extern struct hstor_blist *hstor_list_buckets(struct hstor_client *hstor);

extern bool hstor_get(struct hstor_client *hstor, const char *bucket, const char *key,
	     size_t (*write_cb)(const void *, size_t, size_t, void *),
	     void *user_data, bool want_headers);
extern void *hstor_get_inline(struct hstor_client *hstor, const char *bucket,
			    const char *key, bool want_headers, size_t *len);
extern bool hstor_put(struct hstor_client *hstor, const char *bucket, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char **user_hdrs);
extern bool hstor_put_inline(struct hstor_client *hstor, const char *bucket,
			   const char *key, void *data, uint64_t len,
			   char **user_hdrs);
extern bool hstor_del(struct hstor_client *hstor, const char *bucket, const char *key);

extern struct hstor_keylist *hstor_keys(struct hstor_client *hstor, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys);

#endif /* __HSTOR_H__ */

#ifndef __STC_H__
#define __STC_H__

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

#include <sys/types.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <chunk_msg.h>

struct st_object {
	char		*name;
	char		*time_mod;
	char		*etag;
	uint64_t	size;
	char		*owner;
};

struct st_keylist {
	char		*name;
	GList		*contents;
};

struct st_client {
	char		*host;
	char		*user;
	char		*key;
	bool		verbose;

	int		fd;

	SSL_CTX		*ssl_ctx;
	SSL		*ssl;

	char		req_buf[sizeof(struct chunksrv_req) + CHD_KEY_SZ];
};

extern void stc_free(struct st_client *stc);
extern void stc_free_keylist(struct st_keylist *keylist);
extern void stc_free_object(struct st_object *obj);
extern void stc_init(void);

extern struct st_client *stc_new(const char *service_host, int port,
				 const char *user, const char *secret_key,
				 bool encrypt);
extern bool stc_table_open(struct st_client *stc, const void *key, size_t key_len,
		    uint32_t flags);

extern bool stc_get(struct st_client *stc, const void *key, size_t key_len,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data);
extern void *stc_get_inline(struct st_client *stc,
			    const void *key, size_t key_len, size_t *len);
extern bool stc_get_start(struct st_client *stc, const void *key,
			size_t key_len,int *pfd, uint64_t *len);
extern size_t stc_get_recv(struct st_client *stc, void *data, size_t len);

extern bool stc_put(struct st_client *stc, const void *key, size_t key_len,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, uint32_t flags);
extern bool stc_put_start(struct st_client *stc, const void *key,
			  size_t key_len, uint64_t cont_len, int *pfd,
			  uint32_t flags);
extern size_t stc_put_send(struct st_client *stc, void *data, size_t len);
extern bool stc_put_sync(struct st_client *stc);
extern bool stc_put_inline(struct st_client *stc, const void *key,
			   size_t key_len, void *data, uint64_t len,
			   uint32_t flags);

extern bool stc_del(struct st_client *stc, const void *key, size_t key_len);
extern bool stc_ping(struct st_client *stc);

extern bool stc_check_poke(struct st_client *stc);
extern bool stc_check_status(struct st_client *stc,
			     struct chunk_check_status *out);

extern struct st_keylist *stc_keys(struct st_client *stc);

extern int stc_readport(const char *fname);

static inline void *stc_get_inlinez(struct st_client *stc,
				    const char *key,
				    size_t *len)
{
	return stc_get_inline(stc, key, strlen(key) + 1, len);
}

static inline bool stc_get_startz(struct st_client *stc, const char *key,
				  int *pfd, uint64_t *len)
{
	return stc_get_start(stc, key, strlen(key) + 1, pfd, len);
}

static inline bool stc_put_inlinez(struct st_client *stc, const char *key,
				   void *data, uint64_t len, uint32_t flags)
{
	return stc_put_inline(stc, key, strlen(key) + 1, data, len, flags);
}

static inline bool stc_put_startz(struct st_client *stc, const char *key,
				  uint64_t cont_len, int *pfd, uint32_t flags)
{
	return stc_put_start(stc, key, strlen(key) + 1, cont_len, pfd, flags);
}

static inline bool stc_delz(struct st_client *stc, const char *key)
{
	return stc_del(stc, key, strlen(key) + 1);
}

static inline bool stc_table_openz(struct st_client *stc, const char *key,
				   uint32_t flags)
{
	return stc_table_open(stc, key, strlen(key) + 1, flags);
}

#endif /* __STC_H__ */

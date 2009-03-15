#ifndef __STC_H__
#define __STC_H__

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

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
	bool		ssl;
	int		fd;
};

extern void stc_free(struct st_client *stc);
extern void stc_free_keylist(struct st_keylist *keylist);
extern void stc_free_object(struct st_object *obj);

extern struct st_client *stc_new(const char *service_host, int port,
				 const char *user, const char *secret_key,
				 bool encrypt);

extern bool stc_get(struct st_client *stc, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers);
extern void *stc_get_inline(struct st_client *stc,
			    const char *key, bool want_headers, size_t *len);
extern bool stc_put(struct st_client *stc, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data);
extern bool stc_put_inline(struct st_client *stc, const char *key,
			   void *data, uint64_t len);
extern bool stc_del(struct st_client *stc, const char *key);

extern struct st_keylist *stc_keys(struct st_client *stc);

#endif /* __STC_H__ */

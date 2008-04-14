#ifndef __STC_H__
#define __STC_H__

#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#include <glib.h>

struct st_volume {
	char		*name;
};

struct st_vlist {
	char		*owner;		/* Owner */
	GList		*list;		/* list of st_volume */
};

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
	CURL		*curl;
	char		*host;
	char		*user;
	char		*key;
	bool		verbose;
};

extern void stc_free(struct st_client *stc);

extern struct st_client *stc_new(const char *service_host,
				 const char *user, const char *secret_key);

extern bool stc_get(struct st_client *stc, const char *volume, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers);
extern void *stc_get_inline(struct st_client *stc, const char *volume,
			    const char *key, bool want_headers, size_t *len);
extern bool stc_put(struct st_client *stc, const char *volume,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char *key_out);
extern bool stc_put_inline(struct st_client *stc, const char *volume,
			   void *data, uint64_t len, char *key_out);
extern bool stc_del(struct st_client *stc, const char *volume, const char *key);

extern void stc_free_volume(struct st_volume *vol);
extern void stc_free_vlist(struct st_vlist *vlist);
extern struct st_vlist *stc_list_volumes(struct st_client *stc);

#endif /* __STC_H__ */

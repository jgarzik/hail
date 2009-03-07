#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <glib.h>
#include <pcre.h>
#include "storaged.h"

struct vol_foreach_info {
	GList		*content;
};

static void volume_foreach(gpointer key, gpointer val, gpointer user_data)
{
	struct server_volume *vol = val;
	struct vol_foreach_info *vfi = user_data;
	char *s;

	if (asprintf(&s,
                     "    <Volume>\r\n"
                     "      <Name>%s</Name>\r\n"
                     "    </Volume>\r\n",

		     vol->name) < 0)
		return;

	vfi->content = g_list_append(vfi->content, s);
}

bool service_list(struct client *cli, const char *user)
{
	GList *files = NULL, *content = NULL;
	char *s;
	enum errcode err = InternalError;
	bool rcb;
	struct vol_foreach_info vfi;

	if (asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListAllMyVolumesResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Owner>%s</Owner>\r\n"
"  <Volumes>\r\n",

		     user) < 0)
		goto err_out;

	content = g_list_append(content, s);

	memset(&vfi, 0, sizeof(vfi));

	vfi.content = content;

	g_hash_table_foreach(storaged_srv.volumes, volume_foreach, &vfi);

	content = vfi.content;

	if (asprintf(&s,
"  </Volumes>\r\n"
"</ListAllMyVolumesResult>\r\n") < 0)
		goto err_out_content;

	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, 200, content);

	strlist_free(files);
	g_list_free(content);

	return rcb;

err_out_content:
	strlist_free(content);
err_out:
	strlist_free(files);
	return cli_err(cli, err);
}

bool volume_valid(const char *volume)
{
	int captured[16], rc;
	size_t len;

	if (!volume)
		return false;

	len = strlen(volume);
	if (len < 1 || len > 63)
		return false;

	rc = pcre_exec(patterns[pat_volume_name].re, NULL,
			volume, len, 0, 0, captured, 16);

	return (rc > 0);
}

bool volume_list(struct client *cli, const char *user,
		 struct server_volume *vol)
{
	enum errcode err = InternalError;
	char *s;
	GList *content, *tmpl;
	bool rcb;
	GList *res = NULL;

	/* verify READ access */
	if (!vol) {
		err = NoSuchVolume;
		goto err_out;
	}
	if (!user) {
		err = AccessDenied;
		goto err_out;
	}

	res = vol->be->list_objs(vol);

	asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListVolumeResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n",

		 vol->name);

	content = g_list_append(NULL, s);

	tmpl = res;
	while (tmpl) {
		char *hash;
		char *fn, *name, timestr[50];
		struct stat st;

		name = tmpl->data;
		tmpl = tmpl->next;

		hash = tmpl->data;
		tmpl = tmpl->next;

		fn = fs_obj_pathname(vol, name);
		if (!fn)
			goto do_next;

		if (stat(fn, &st) < 0) {
			syslog(LOG_ERR, "blist stat(%s) failed: %s",
				fn, strerror(errno));
			st.st_mtime = 0;
			st.st_size = 0;
		} else
			st.st_size -= sizeof(struct be_fs_obj_hdr);

		asprintf(&s,
                         "  <Contents>\r\n"
			 "    <Name>%s</Name>\r\n"
                         "    <LastModified>%s</LastModified>\r\n"
                         "    <ETag>%s</ETag>\r\n"
                         "    <Size>%llu</Size>\r\n"
                         "    <Owner>%s</Owner>\r\n"
                         "  </Contents>\r\n",

			 name,
			 time2str(timestr, st.st_mtime),
			 hash,
			 (unsigned long long) st.st_size,
			 user);

		content = g_list_append(content, s);

do_next:
		free(name);
		free(hash);
		free(fn);
	}

	g_list_free(res);

	s = strdup("</ListVolumeResult>\r\n");
	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, 200, content);

	g_list_free(content);

	return rcb;

err_out:
	return cli_err(cli, err);
}


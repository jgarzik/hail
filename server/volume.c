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
#include <sqlite3.h>
#include <alloca.h>
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

struct volume_list_info {
	GList *res;
	int n_keys;
	const char *next_key;
};

static bool volume_list_iter(const char *name,
			     const char *hash, struct volume_list_info *bli)
{
	bli->res = g_list_append(bli->res, strdup(name));
	bli->res = g_list_append(bli->res, strdup(hash));

	return false;		/* continue traversal */
}

bool volume_list(struct client *cli, const char *user,
		 struct server_volume *vol)
{
	enum errcode err = InternalError;
	char *s;
	int rc;
	GList *content, *tmpl;
	struct volume_list_info bli;
	char *zsql;
	const char *dummy;
	bool rcb;
	sqlite3_stmt *select;
	char *volume;

	/* verify READ access */
	if (!user || !vol) {
		err = AccessDenied;
		goto err_out;
	}

	volume = vol->name;

	/* build SQL SELECT statement */
	zsql = alloca(80);

	strcpy(zsql, "select name, hash from objects where volume = ?");

	rc = sqlite3_prepare_v2(sqldb, zsql, -1, &select, &dummy);
	if (rc != SQLITE_OK)
		goto err_out_param;

	/* exec SQL query */
	sqlite3_bind_text(select, 1, volume, -1, SQLITE_STATIC);

	memset(&bli, 0, sizeof(bli));

	/* iterate through each returned SQL data row */
	while (1) {
		const char *name, *hash;

		rc = sqlite3_step(select);
		if (rc != SQLITE_ROW)
			break;

		name = (const char *) sqlite3_column_text(select, 0);
		hash = (const char *) sqlite3_column_text(select, 1);

		if (!volume_list_iter(name, hash, &bli))
			break;
	}

	sqlite3_finalize(select);

	asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListVolumeResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n",

		 volume);

	content = g_list_append(NULL, s);

	tmpl = bli.res;
	while (tmpl) {
		char *hash;
		char *fn, *name, timestr[64];
		struct stat st;

		name = tmpl->data;
		tmpl = tmpl->next;

		hash = tmpl->data;
		tmpl = tmpl->next;

		if (asprintf(&fn, "%s/%s", vol->path, name) < 0)
			goto do_next;

		if (stat(fn, &st) < 0) {
			syslog(LOG_ERR, "blist stat(%s) failed: %s",
				fn, strerror(errno));
			st.st_mtime = 0;
			st.st_size = 0;
		}

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

	g_list_free(bli.res);

	s = strdup("</ListVolumeResult>\r\n");
	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, 200, content);

	g_list_free(content);

	return rcb;

err_out_param:
err_out:
	return cli_err(cli, err);
}


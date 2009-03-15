#define _GNU_SOURCE
#include "chunkd-config.h"
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
#include "chunkd.h"

bool volume_list(struct client *cli, const char *user)
{
	enum errcode err = InternalError;
	char *s;
	GList *content, *tmpl;
	bool rcb;
	GList *res = NULL;

	/* verify READ access */
	if (!user) {
		err = AccessDenied;
		goto err_out;
	}

	res = fs_list_objs();

	asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListVolumeResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n",

		 "volume");

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

		fn = fs_obj_pathname(name);
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


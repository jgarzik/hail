
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

#define _GNU_SOURCE
#include "hail-config.h"

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>
#include <cld_common.h>
#include <chunk-private.h>
#include <chunkc.h>
#include "test.h"

enum { BUFLEN = 8192 };

struct config_context {
	char *text;

	char *path;
};

static void cfg_elm_start(GMarkupParseContext *context,
			  const gchar	 *element_name,
			  const gchar    **attribute_names,
			  const gchar    **attribute_values,
			  gpointer       user_data,
			  GError         **error)
{
	;
}

static void cfg_elm_end(GMarkupParseContext *context,
			const gchar	*element_name,
			gpointer	user_data,
			GError		**error)
{
	struct config_context *cc = user_data;

	if (!strcmp(element_name, "Path")) {
		OK(cc->text);
		free(cc->path);
		cc->path = cc->text;
		cc->text = NULL;
	} else {
		free(cc->text);
		cc->text = NULL;
	}
}

static bool str_n_isspace(const char *s, size_t n)
{
	char c;
	size_t i;

	for (i = 0; i < n; i++) {
		c = *s++;
		if (!isspace(c))
			return false;
	}
	return true;
}

static void cfg_elm_text(GMarkupParseContext *context,
			 const gchar	*text,
			 gsize		text_len,
			 gpointer	user_data,
			 GError		**error)
{
	struct config_context *cc = user_data;

	free(cc->text);
	if (str_n_isspace(text, text_len))
		cc->text = NULL;
	else
		cc->text = g_strndup(text, text_len);
}

static const GMarkupParser cfg_parse_ops = {
	.start_element		= cfg_elm_start,
	.end_element		= cfg_elm_end,
	.text			= cfg_elm_text,
};

static void read_config(struct config_context *cc)
{
	GMarkupParseContext* parser;
	char *top, *cfg;
	char *text;
	gsize len;
	int rc;

	top = getenv("top_srcdir");
	OK(top);

	rc = asprintf(&cfg, "%s/test/chunkd/" TEST_CHUNKD_CFG, top);
	OK(rc > 0);

	rc = g_file_get_contents(cfg, &text, &len, NULL);
	OK(rc);

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, cc, NULL);
	OK(parser);

	rc = g_markup_parse_context_parse(parser, text, len, NULL);
	OK(rc);

	g_markup_parse_context_free(parser);
	free(text);
	free(cfg);
}

static void hexstr(const unsigned char *buf, size_t buf_len, char *outstr)
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < buf_len; i++) {
		outstr[i * 2]       = hex[(buf[i] & 0xF0) >> 4];
		outstr[(i * 2) + 1] = hex[(buf[i] & 0x0F)     ];
	}

	outstr[buf_len * 2] = 0;
}

static char *fs_obj_pathname(const char *path, uint32_t table_id,
			     const void *key, size_t key_len)
{
	char *s = NULL;
	char prefix[PREFIX_LEN + 1];
	unsigned char md[SHA256_DIGEST_LENGTH];
	char mdstr[(SHA256_DIGEST_LENGTH * 2) + 1];
	int rc;

	if (!table_id || !key || !key_len)
		return NULL;

	SHA256(key, key_len, md);
	hexstr(md, SHA256_DIGEST_LENGTH, mdstr);

	memcpy(prefix, mdstr, PREFIX_LEN);
	prefix[PREFIX_LEN] = 0;

	rc = asprintf(&s, MDB_TPATH_FMT "/%s/%s", path, table_id,
		      prefix, mdstr + PREFIX_LEN);
	OK(rc != -1);

	return s;
}

static bool be_file_verify(const char *fn)
{
	int fd;

	/* stat(2) is nice and all, but whatever. */
	fd = open(fn, O_RDONLY);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static bool be_file_damage(const char *fn)
{
	int fd;
	char buf[1];
	ssize_t rcs;
	off_t rco;

	fd = open(fn, O_WRONLY);
	if (fd < 0)
		return false;

	/*
	 * This puts the damage at data size minus the mysterious header size.
	 */
	rco = lseek(fd, BUFLEN, SEEK_SET);
	if (rco == (off_t)-1) {
		close(fd);
		return false;
	}

	buf[0] = 0;
	rcs = write(fd, buf, 1);
	if (rcs <= 0) {
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

int main(int argc, char *argv[])
{
	static char key[] = "selfcheck-test-key";
	int port;
	char *buf;
	struct config_context ctx;
	struct st_client *stc;
	char *fn;
	size_t len;
	void *mem;
	struct chunk_check_status status1, status2;
	int cnt;
	bool rcb;

	setlocale(LC_ALL, "C");

	stc_init();
	SSL_library_init();

	buf = malloc(BUFLEN);
	OK(buf);
	memset(buf, 0x55, BUFLEN);

	port = hail_readport(TEST_PORTFILE);
	OK(port > 0);

	/*
	 * Step 0: read and parse the configuration.
	 */
	memset(&ctx, 0, sizeof(struct config_context));
	read_config(&ctx);
	OK(ctx.path);		/* must have a path */

	/*
	 * Step 1: create the object
	 */
	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, false);
	OK(stc);
	rcb = stc_table_openz(stc, TEST_TABLE, 0);
	OK(rcb);
	rcb = stc_put_inline(stc, key, sizeof(key), buf, BUFLEN, 0);
	OK(rcb);
	stc_free(stc);

	/*
	 * Step 2: verify the back-end file is created
	 * N.B. We guess the tabled ID to be 1, sice all tests use the same
	 *      table and they are numbered sequentially on a fresh DB.
	 */
	fn = fs_obj_pathname(ctx.path, 1, key, sizeof(key));
	OK(fn);
	rcb = be_file_verify(fn);
	OK(rcb);

	/*
	 * Step 3: damage the back-end file and wait, because:
	 * 1) the server may be quite busy walking numerous objects
	 * 2) the build system may be overloaded
	 */
	rcb = be_file_damage(fn);
	OK(rcb);

	/*
	 * Step 4: force self-check and make sure it runs
	 */
	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, false);
	OK(stc);
	rcb = stc_check_status(stc, &status1);
	OK(rcb);
	rcb = stc_check_start(stc);
	OK(rcb);
	cnt = 0;
	for (;;) {
		sleep(2);
		rcb = stc_check_status(stc, &status2);
		OK(rcb);
		if (status2.lastdone != status1.lastdone &&
		    status2.state != chk_Active)
			break;
		++cnt;
		OK(cnt < 15);
	}
	stc_free(stc);

	/*
	 * Step 5: verify that the damaged object is removed
	 * This is, strictly speaking, not necessary. The true test is
	 * trying to access the keyed object through the chunkserver's API.
	 * But since we have the function already, might as well use it.
	 */
	rcb = be_file_verify(fn);
	OK(!rcb);

	free(fn);
	fn = NULL;

	/*
	 * Step 6: verify that we didn't crash the chunkserver and that
	 * the object we created and damaged is not considered present anymore.
	 */
	stc = stc_new(TEST_HOST, port, TEST_USER, TEST_USER_KEY, false);
	OK(stc);
	rcb = stc_table_openz(stc, TEST_TABLE, 0);
	OK(rcb);
	mem = stc_get_inline(stc, key, sizeof(key), &len);
	OK(!mem);
	stc_free(stc);

	return 0;
}

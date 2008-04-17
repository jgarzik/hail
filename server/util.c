#define _GNU_SOURCE
#include "storaged-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <sqlite3.h>
#include "storaged.h"

static const char *sql_stmt_text[] = {
	[st_begin] =
	"begin transaction",

	[st_commit] =
	"commit transaction",

	[st_rollback] =
	"rollback transaction",

	[st_volume_objects] =
	"select * from objects where volume = ?",

	[st_add_obj] =
	"insert into objects values (?, ?, ?, ?)",

	[st_del_obj] =
	"delete from objects where volume = ? and name = ?",

	[st_object] =
	"select * from objects where volume = ? and name = ?",
};

size_t strlist_len(GList *l)
{
	GList *tmp = l;
	size_t sum = 0;

	while (tmp) {
		sum += strlen(tmp->data);
		tmp = tmp->next;
	}

	return sum;
}

void __strlist_free(GList *l)
{
	GList *tmp = l;

	while (tmp) {
		free(tmp->data);
		tmp->data = NULL;
		tmp = tmp->next;
	}
}

void strlist_free(GList *l)
{
	__strlist_free(l);
	g_list_free(l);
}

void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

void strup(char *s)
{
	while (*s) {
		*s = toupper(*s);
		s++;
	}
}

int write_pid_file(const char *pid_fn)
{
	char str[32], *s;
	size_t bytes;

	/* build file data */
	sprintf(str, "%u\n", getpid());
	s = str;
	bytes = strlen(s);

	/* exclusive open */
	int fd = open(pid_fn, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslogerr(pid_fn);
		return -errno;
	}

	/* write file data */
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			syslogerr("pid data write failed");
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if ((fsync(fd) < 0) || (close(fd) < 0)) {
		syslogerr("pid file sync/close failed");
		goto err_out;
	}

	return 0;

err_out:
	close(fd);
	unlink(pid_fn);
	return -errno;
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		syslog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(errno));
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			syslog(LOG_ERR, "%s F_SETFL: %s", prefix, strerror(errno));
			rc = -errno;
		}

	return rc;
}

void shastr(const unsigned char *digest, char *outstr)
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		outstr[i * 2]       = hex[(digest[i] & 0xF0) >> 4];
		outstr[(i * 2) + 1] = hex[(digest[i] & 0x0F)     ];
	}

	outstr[SHA_DIGEST_LENGTH * 2] = 0;
}

bool sql_begin(struct database *db)
{
	int rc = sqlite3_step(db->prep_stmts[st_begin]);
	sqlite3_reset(db->prep_stmts[st_begin]);
	return (rc == SQLITE_DONE);
}

bool sql_commit(struct database *db)
{
	int rc = sqlite3_step(db->prep_stmts[st_commit]);
	sqlite3_reset(db->prep_stmts[st_commit]);
	return (rc == SQLITE_DONE);
}

bool sql_rollback(struct database *db)
{
	int rc = sqlite3_step(db->prep_stmts[st_rollback]);
	sqlite3_reset(db->prep_stmts[st_rollback]);
	return (rc == SQLITE_DONE);
}

struct database *db_open(void)
{
	char db_fn[PATH_MAX + 1];
	unsigned int i;
	int rc;
	struct database *db;

	db = calloc(1, sizeof(*db));
	if (!db)
		return NULL;

	sprintf(db_fn, "%s/master.db", storaged_srv.data_dir);

	rc = sqlite3_open(db_fn, &db->sqldb);
	if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "sqlite3_open failed");
		free(db);
		return NULL;
	}

	for (i = 0; i <= st_last; i++) {
		const char *dummy;

		rc = sqlite3_prepare_v2(db->sqldb, sql_stmt_text[i], -1,
					&db->prep_stmts[i], &dummy);
		g_assert(rc == SQLITE_OK);
	}

	return db;
}

void db_close(struct database *db)
{
	int i;

	for (i = 0; i <= st_last; i++)
		sqlite3_finalize(db->prep_stmts[i]);
	sqlite3_close(db->sqldb);

	free(db);
}

static struct {
	char		*text;
	bool		in_vol;
	bool		in_ssl;
	bool		in_listen;
	bool		have_ssl;
	struct server_volume *tmp_vol;
	struct listen_cfg tmp_listen;
} cfg_context;

static void free_server_volume(struct server_volume *v)
{
	if (!v)
		return;
	
	free(v->name);
	free(v->path);
	free(v);
}

static void __free_server_volume(gpointer data)
{
	free_server_volume(data);
}

static void cfg_elm_text (GMarkupParseContext *context,
			  const gchar	*text,
			  gsize		text_len,  
			  gpointer	user_data,
			  GError	**error)
{
	free(cfg_context.text);
	cfg_context.text = strndup(text, text_len);
}

static void cfg_elm_start (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 const gchar     **attribute_names,
			 const gchar     **attribute_values,
			 gpointer     user_data,
			 GError	     **error)
{
	if (!strcmp(element_name, "Volume")) {
		cfg_context.in_vol = true;
		free_server_volume(cfg_context.tmp_vol);
		cfg_context.tmp_vol = calloc(1, sizeof(struct server_volume));
	}
	else if (!strcmp(element_name, "SSL"))
		cfg_context.in_ssl = true;
	else if (!strcmp(element_name, "Listen")) {
		cfg_context.in_listen = true;
		memset(&cfg_context.tmp_listen, 0,
			sizeof(cfg_context.tmp_listen));
	}
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct stat st;

	if (!strcmp(element_name, "PID") && cfg_context.text) {
		storaged_srv.pid_file = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (!strcmp(element_name, "DB") && cfg_context.text) {
		if (stat(cfg_context.text, &st) < 0) {
			syslog(LOG_ERR, "stat(2) cfgfile DB '%s' failed: %s",
			       cfg_context.text, strerror(errno));
			return;
		}

		if (!S_ISDIR(st.st_mode)) {
			syslog(LOG_ERR, "DB in cfgfile not a dir: '%s'",
			       cfg_context.text);
			return;
		}

		storaged_srv.data_dir = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (!strcmp(element_name, "Volume")) {
		cfg_context.in_vol = false;
		if (cfg_context.tmp_vol->name &&
		    cfg_context.tmp_vol->path &&
		    cfg_context.tmp_vol->be)
			g_hash_table_replace(storaged_srv.volumes,
				cfg_context.tmp_vol->name,
				cfg_context.tmp_vol);
		else
			free_server_volume(cfg_context.tmp_vol);
		cfg_context.tmp_vol = NULL;
	}

	else if (cfg_context.in_vol && cfg_context.text &&
		 !strcmp(element_name, "Name")) {
		if (!volume_valid(cfg_context.text)) {
			syslog(LOG_ERR, "invalid volume name (req. DNS rules): '%s'",
				cfg_context.text);
			return;
		}

		free(cfg_context.tmp_vol->name);
		cfg_context.tmp_vol->name = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (cfg_context.in_vol && cfg_context.text &&
		 !strcmp(element_name, "Path")) {
		if (stat(cfg_context.text, &st) < 0) {
			syslog(LOG_ERR, "stat(2) cfgfile Path '%s' failed: %s",
			       cfg_context.text, strerror(errno));
			return;
		}

		if (!S_ISDIR(st.st_mode)) {
			syslog(LOG_ERR, "Path in cfgfile not a dir: %s",
			       cfg_context.text);
			return;
		}

		free(cfg_context.tmp_vol->path);
		cfg_context.tmp_vol->path = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (cfg_context.in_vol && cfg_context.text &&
		 !strcmp(element_name, "Method")) {
		struct backend_info *be;

		be = g_hash_table_lookup(storaged_srv.backends,
					 cfg_context.text);
		if (!be) {
			syslog(LOG_ERR, "cfgfile Method '%s' unknown",
			       cfg_context.text);
			return;
		}

		cfg_context.tmp_vol->be = be;

		free(cfg_context.text);
		cfg_context.text = NULL;
	}

	else if (!strcmp(element_name, "SSL"))
		cfg_context.in_ssl = false;

	else if (cfg_context.in_ssl && cfg_context.text &&
		 !strcmp(element_name, "PrivateKey")) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, cfg_context.text,
						SSL_FILETYPE_PEM) <= 0)
			syslog(LOG_ERR, "Failed to read SSL private key '%s'",
				cfg_context.text);

		free(cfg_context.text);
		cfg_context.text = NULL;

		cfg_context.have_ssl = true;
	}

	else if (cfg_context.in_ssl && cfg_context.text &&
		 !strcmp(element_name, "Cert")) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, cfg_context.text,
						 SSL_FILETYPE_PEM) <= 0)
			syslog(LOG_ERR, "Failed to read SSL certificate '%s'",
				cfg_context.text);

		free(cfg_context.text);
		cfg_context.text = NULL;

		cfg_context.have_ssl = true;
	}

	else if (!strcmp(element_name, "Listen")) {
		struct listen_cfg *cfg;

		cfg_context.in_listen = false;

		if (!cfg_context.tmp_listen.port) {
			free(cfg_context.tmp_listen.node);
			cfg_context.tmp_listen.node = NULL;
			cfg_context.tmp_listen.encrypt = false;
			syslog(LOG_WARNING, "cfgfile: TCP port not specified in Listen");
			return;
		}

		cfg = malloc(sizeof(*cfg));
		if (!cfg) {
			syslog(LOG_ERR, "OOM");
			return;
		}

		memcpy(cfg, &cfg_context.tmp_listen, sizeof(*cfg));
		storaged_srv.listeners =
			g_list_append(storaged_srv.listeners, cfg);
	}

	else if (cfg_context.in_listen && cfg_context.text &&
		 !strcmp(element_name, "Port")) {
		int i = atoi(cfg_context.text);

		if (i > 0 && i < 65536) {
			free(cfg_context.tmp_listen.port);
			cfg_context.tmp_listen.port = cfg_context.text;
		} else {
			syslog(LOG_WARNING, "cfgfile Port '%s' invalid, ignoring",
				cfg_context.text);
			free(cfg_context.text);
		}

		cfg_context.text = NULL;
	}

	else if (cfg_context.in_listen && cfg_context.text &&
		 !strcmp(element_name, "Node")) {
		cfg_context.tmp_listen.node = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (cfg_context.in_listen && cfg_context.text &&
		 !strcmp(element_name, "Encrypt")) {
		if (!strcasecmp(cfg_context.text, "yes") ||
		    !strcasecmp(cfg_context.text, "true"))
			cfg_context.tmp_listen.encrypt = true;

		free(cfg_context.text);
		cfg_context.text = NULL;
	}

}

static const GMarkupParser cfg_parse_ops = {
	.start_element		= cfg_elm_start,
	.end_element		= cfg_elm_end,
	.text			= cfg_elm_text,
};

void read_config(void)
{
	GMarkupParseContext* parser;
	char *text;
	gsize len;

	storaged_srv.volumes = g_hash_table_new_full(
		g_str_hash, g_str_equal, NULL, __free_server_volume);
	if (!storaged_srv.volumes) {
		syslog(LOG_ERR, "OOM in read_config");
		exit(1);
	}

	if (!g_file_get_contents(storaged_srv.config, &text, &len, NULL)) {
		syslog(LOG_ERR, "failed to read config file %s",
			storaged_srv.config);
		exit(1);
	}
	
	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, NULL, NULL);
	if (!parser) {
		syslog(LOG_ERR, "g_markup_parse_context_new failed");
		exit(1);
	}

	if (!g_markup_parse_context_parse(parser, text, len, NULL)) {
		syslog(LOG_ERR, "config file parse failure");
		exit(1);
	}

	g_markup_parse_context_free(parser);
	free(text);

	if (!storaged_srv.volumes) {
		syslog(LOG_ERR, "error: no volumes defined in cfg file");
		exit(1);
	}

	if (!storaged_srv.data_dir) {
		syslog(LOG_ERR, "error: no database dir defined in cfg file");
		exit(1);
	}

	if (!cfg_context.have_ssl) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	} else if (cfg_context.have_ssl &&
		   !SSL_CTX_check_private_key(ssl_ctx)) {
		syslog(LOG_ERR, "SSL private key does not match certificate public key");
		exit(1);
	}

	if (!storaged_srv.listeners) {
		syslog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}
}

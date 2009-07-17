
/*
 * Copyright (c) 2009 Red Hat, Inc.
 */
#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>
#include "chunkd.h"

struct config_context {
	char		*text;
	bool		in_ssl;
	bool		in_listen;
	bool		have_ssl;
	char		*vol_path;
	struct listen_cfg tmp_listen;
};

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

static void cfg_elm_text (GMarkupParseContext *context,
			  const gchar	*text,
			  gsize		text_len,
			  gpointer	user_data,
			  GError	**error)
{
	struct config_context *cc = user_data;

	free(cc->text);
	if (str_n_isspace(text, text_len))
		cc->text = NULL;
	else
		cc->text = g_strndup(text, text_len);
}

static void cfg_elm_start (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 const gchar     **attribute_names,
			 const gchar     **attribute_values,
			 gpointer     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;

	if (!strcmp(element_name, "SSL"))
		cc->in_ssl = true;
	else if (!strcmp(element_name, "Listen")) {
		if (!cc->in_listen) {
			cc->in_listen = true;
		} else {
			syslog(LOG_ERR, "Nested Listen in configuration");
		}
	}
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;
	struct stat st;

	if (!strcmp(element_name, "PID") && cc->text) {
		if (chunkd_srv.pid_file) {
			/* Silent about command line override. */
			free(cc->text);
		} else {
			chunkd_srv.pid_file = cc->text;
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Path") && cc->text) {
		if (stat(cc->text, &st) < 0) {
			syslog(LOG_ERR, "stat(2) cfgfile Path '%s' failed: %s",
			       cc->text, strerror(errno));
			return;
		}

		if (!S_ISDIR(st.st_mode)) {
			syslog(LOG_ERR, "Path in cfgfile not a dir: %s",
			       cc->text);
			return;
		}

		chunkd_srv.vol_path = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "SSL"))
		cc->in_ssl = false;

	else if (cc->in_ssl && cc->text && !strcmp(element_name, "PrivateKey")) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, cc->text,
						SSL_FILETYPE_PEM) <= 0)
			syslog(LOG_ERR, "Failed to read SSL private key '%s'",
				cc->text);

		free(cc->text);
		cc->text = NULL;

		cc->have_ssl = true;
	}

	else if (cc->in_ssl && cc->text && !strcmp(element_name, "Cert")) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, cc->text,
						 SSL_FILETYPE_PEM) <= 0)
			syslog(LOG_ERR, "Failed to read SSL certificate '%s'",
				cc->text);

		free(cc->text);
		cc->text = NULL;

		cc->have_ssl = true;
	}

	else if (!strcmp(element_name, "Listen")) {
		struct listen_cfg *cfg;

		if (cc->text) {
			syslog(LOG_WARNING,
			       "cfgfile: Extra text '%s' in Listen",
			       cc->text);
			free(cc->text);
			cc->text = NULL;
			return;
		}

		cc->in_listen = false;

		if (!cc->tmp_listen.port) {
			free(cc->tmp_listen.node);
			memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
			syslog(LOG_WARNING, "cfgfile: TCP port not specified in Listen");
			return;
		}

		cfg = malloc(sizeof(*cfg));
		if (!cfg) {
			free(cc->tmp_listen.node);
			free(cc->tmp_listen.port);
			memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
			syslog(LOG_ERR, "OOM");
			return;
		}

		memcpy(cfg, &cc->tmp_listen, sizeof(*cfg));
		chunkd_srv.listeners =
			g_list_append(chunkd_srv.listeners, cfg);
		memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
	}

	else if (cc->in_listen && cc->text && !strcmp(element_name, "Port")) {
		int i = atoi(cc->text);

		if (i > 0 && i < 65536) {
			free(cc->tmp_listen.port);
			cc->tmp_listen.port = cc->text;
		} else {
			syslog(LOG_WARNING, "cfgfile Port '%s' invalid, ignoring",
				cc->text);
			free(cc->text);
		}

		cc->text = NULL;
	}

	else if (cc->in_listen && cc->text && !strcmp(element_name, "Node")) {
		cc->tmp_listen.node = cc->text;
		cc->text = NULL;
	}

	else if (cc->in_listen && cc->text &&
		 !strcmp(element_name, "Encrypt")) {
		if (!strcasecmp(cc->text, "yes") ||
		    !strcasecmp(cc->text, "true"))
			cc->tmp_listen.encrypt = true;

		free(cc->text);
		cc->text = NULL;
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
	struct config_context ctx;

	memset(&ctx, 0, sizeof(struct config_context));

	if (!g_file_get_contents(chunkd_srv.config, &text, &len, NULL)) {
		syslog(LOG_ERR, "failed to read config file %s",
			chunkd_srv.config);
		exit(1);
	}

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, &ctx, NULL);
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

	if (!chunkd_srv.vol_path) {
		syslog(LOG_ERR, "error: no volume Path defined in cfg file");
		exit(1);
	}

	if (!ctx.have_ssl) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	} else if (ctx.have_ssl && !SSL_CTX_check_private_key(ssl_ctx)) {
		syslog(LOG_ERR, "SSL private key does not match certificate public key");
		exit(1);
	}

	if (!chunkd_srv.listeners) {
		syslog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}

	if (!chunkd_srv.pid_file) {
		if (!(chunkd_srv.pid_file = strdup("/var/run/chunkd.pid"))) {
			syslog(LOG_ERR, "no core");
			exit(1);
		}
	}
}


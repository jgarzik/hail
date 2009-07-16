
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

static struct {
	char		*text;
	bool		in_ssl;
	bool		in_listen;
	bool		have_ssl;
	char		*vol_path;
	struct listen_cfg tmp_listen;
} cfg_context;

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
	free(cfg_context.text);
	if (str_n_isspace(text, text_len))
		cfg_context.text = NULL;
	else
		cfg_context.text = g_strndup(text, text_len);
}

static void cfg_elm_start (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 const gchar     **attribute_names,
			 const gchar     **attribute_values,
			 gpointer     user_data,
			 GError	     **error)
{
	if (!strcmp(element_name, "SSL"))
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
		chunkd_srv.pid_file = cfg_context.text;
		cfg_context.text = NULL;
	}

	else if (!strcmp(element_name, "Path") && cfg_context.text) {
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

		chunkd_srv.vol_path = cfg_context.text;
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

		if (cfg_context.text) {
			syslog(LOG_WARNING,
			       "cfgfile: Extra text '%s' in Listen",
			       cfg_context.text);
			free(cfg_context.text);
			cfg_context.text = NULL;
			return;
		}

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
		chunkd_srv.listeners =
			g_list_append(chunkd_srv.listeners, cfg);
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

	if (!g_file_get_contents(chunkd_srv.config, &text, &len, NULL)) {
		syslog(LOG_ERR, "failed to read config file %s",
			chunkd_srv.config);
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

	if (!chunkd_srv.vol_path) {
		syslog(LOG_ERR, "error: no volume Path defined in cfg file");
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

	if (!chunkd_srv.listeners) {
		syslog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}
}


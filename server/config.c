
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

void app_log(const char *fmt, ...);	/* FIXME: get rid of this */

struct config_context {
	char		*text;
	bool		badnid;
	bool		in_ssl;
	bool		in_listen;
	bool		have_ssl;
	char		*vol_path;

	bool		in_geo;
	char		*geo_area, *geo_zone, *geo_rack;

	bool		in_cld;
	unsigned short	cld_port;
	char		*cld_host;

	struct listen_cfg tmp_listen;
};

static bool is_good_cell_name(const char *s)
{
	char c;
	int n;

	n = 0;
	while ((c = *s++) != 0) {
		if (n >= 64)
			return false;
		/* whatever we allow in the future, we must filter '/' */
		if (!(isalpha(c) || isdigit(c) ||
		    c == '-' || c == '_' || c == '.'))
			return false;
		n++;
	}
	return true;
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
			applog(LOG_ERR, "Nested Listen in configuration");
		}
	}
	else if (!strcmp(element_name, "Geo")) {
		if (!cc->in_geo) {
			cc->in_geo = true;
		} else {
			applog(LOG_ERR, "Nested Geo in configuration");
		}
	}
	else if (!strcmp(element_name, "CLD")) {
		if (!cc->in_cld) {
			cc->in_cld = true;
		} else {
			applog(LOG_ERR, "Nested CLD in configuration");
		}
	}
}

static void cfg_elm_end_listen(struct config_context *cc)
{
	struct listen_cfg *cfg;

	if (cc->text) {
		applog(LOG_WARNING, "cfgfile: Extra text '%s' in Listen",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		return;
	}

	if (!cc->tmp_listen.port) {
		free(cc->tmp_listen.node);
		memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
		applog(LOG_WARNING, "cfgfile: TCP port not specified in Listen");
		return;
	}

	cfg = malloc(sizeof(*cfg));
	if (!cfg) {
		free(cc->tmp_listen.node);
		free(cc->tmp_listen.port);
		memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
		applog(LOG_ERR, "OOM");
		return;
	}

	memcpy(cfg, &cc->tmp_listen, sizeof(*cfg));
	chunkd_srv.listeners = g_list_append(chunkd_srv.listeners, cfg);
	memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
}

static void cfg_elm_end_geo(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "cfgfile: Extra text '%s' in Geo",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		goto err_out;
	}

	free(chunkd_srv.loc.area);
	chunkd_srv.loc.area = cc->geo_area;
	cc->geo_area = NULL;
	free(chunkd_srv.loc.zone);
	chunkd_srv.loc.zone = cc->geo_zone;
	cc->geo_zone = NULL;
	free(chunkd_srv.loc.rack);
	chunkd_srv.loc.rack = cc->geo_rack;
	cc->geo_rack = NULL;

	return;

err_out:
	free(cc->geo_area);
	cc->geo_area = NULL;
	free(cc->geo_zone);
	cc->geo_zone = NULL;
	free(cc->geo_rack);
	cc->geo_rack = NULL;
}

static void cfg_elm_end_cld(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "Extra text in CLD element: \"%s\"",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		goto end;
	}

	if (!cc->cld_host) {
		applog(LOG_WARNING, "No host for CLD element");
		goto end;
	}
	if (!cc->cld_port) {
		applog(LOG_WARNING, "No port for CLD element");
		goto end;
	}

	cldu_add_host(cc->cld_host, cc->cld_port, app_log);

end:
	free(cc->cld_host);
	cc->cld_host = NULL;
	cc->cld_port = 0;
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;
	struct stat st;
	long n;

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
			applog(LOG_ERR, "stat(2) cfgfile Path '%s' failed: %s",
			       cc->text, strerror(errno));
			return;
		}

		if (!S_ISDIR(st.st_mode)) {
			applog(LOG_ERR, "Path in cfgfile not a dir: %s",
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
			applog(LOG_ERR, "Failed to read SSL private key '%s'",
				cc->text);

		free(cc->text);
		cc->text = NULL;

		cc->have_ssl = true;
	}

	else if (cc->in_ssl && cc->text && !strcmp(element_name, "Cert")) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, cc->text,
						 SSL_FILETYPE_PEM) <= 0)
			applog(LOG_ERR, "Failed to read SSL certificate '%s'",
				cc->text);

		free(cc->text);
		cc->text = NULL;

		cc->have_ssl = true;
	}

	else if (!strcmp(element_name, "Listen")) {
		cfg_elm_end_listen(cc);
		cc->in_listen = false;
	}

	else if (!strcmp(element_name, "CLD")) {
		cfg_elm_end_cld(cc);
		cc->in_cld = false;
	}

	else if (!strcmp(element_name, "Port")) {
		if (!cc->text) {
			applog(LOG_WARNING, "Port element empty");
			return;
		}

		if (cc->in_listen) {
			n = strtol(cc->text, NULL, 10);
			if (n > 0 && n < 65536) {
				free(cc->tmp_listen.port);
				cc->tmp_listen.port = cc->text;
			} else {
				applog(LOG_WARNING,
				       "Port '%s' invalid, ignoring", cc->text);
				free(cc->text);
			}
			cc->text = NULL;
		} else if (cc->in_cld) {
			n = strtol(cc->text, NULL, 10);
			if (n > 0 && n < 65536)
				cc->cld_port = n;
			else
				applog(LOG_WARNING,
				       "Port '%s' invalid, ignoring", cc->text);
			free(cc->text);
			cc->text = NULL;
		} else {
			applog(LOG_WARNING,
			       "Port element not in Listen or CLD");
			return;
		}
	}

	else if (cc->in_listen && cc->text && !strcmp(element_name, "Node")) {
		cc->tmp_listen.node = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Host")) {
		if (!cc->text) {
			applog(LOG_WARNING, "Host element empty");
			return;
		}

		if (cc->in_cld) {
			free(cc->cld_host);
			cc->cld_host = cc->text;
			cc->text = NULL;
		} else {
			applog(LOG_WARNING, "Host element not in CLD");
		}
	}

	else if (cc->in_listen && cc->text &&
		 !strcmp(element_name, "Encrypt")) {
		if (!strcasecmp(cc->text, "yes") ||
		    !strcasecmp(cc->text, "true"))
			cc->tmp_listen.encrypt = true;

		free(cc->text);
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Cell") && cc->text) {
		free(chunkd_srv.cell);
		chunkd_srv.cell = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "NID") && cc->text) {
		n = strtol(cc->text, NULL, 10);
		if (n <= 0 || n >= LONG_MAX) {
			applog(LOG_ERR, "NID '%s' is invalid", cc->text);
			cc->badnid = true;
			free(cc->text);
			cc->text = NULL;
			return;
		}
		/*
		 * Well-meaning but misguided users are quick to generate
		 * overlong NIDs for various reasons, like using a date with
		 * nanoseconds. On 32-bitters we just truncate them and
		 * hope nobody notices.
		 */
		chunkd_srv.nid = n;
		free(cc->text);
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Geo") && cc->text) {
		cfg_elm_end_geo(cc);
		cc->in_geo = false;
	}

	else {
		applog(LOG_WARNING, "Unknown element \"%s\"", element_name);
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
		applog(LOG_ERR, "failed to read config file %s",
			chunkd_srv.config);
		exit(1);
	}

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, &ctx, NULL);
	if (!parser) {
		applog(LOG_ERR, "g_markup_parse_context_new failed");
		exit(1);
	}

	if (!g_markup_parse_context_parse(parser, text, len, NULL)) {
		applog(LOG_ERR, "config file parse failure");
		exit(1);
	}

	g_markup_parse_context_free(parser);
	free(text);

	if (!chunkd_srv.vol_path) {
		applog(LOG_ERR, "error: no volume Path defined in cfg file");
		exit(1);
	}

	if (!ctx.have_ssl) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	} else if (ctx.have_ssl && !SSL_CTX_check_private_key(ssl_ctx)) {
		applog(LOG_ERR, "SSL private key does not match certificate public key");
		exit(1);
	}

	if (!chunkd_srv.listeners) {
		applog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}

	if (!chunkd_srv.pid_file) {
		if (!(chunkd_srv.pid_file = strdup("/var/run/chunkd.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	if (chunkd_srv.cell && !is_good_cell_name(chunkd_srv.cell)) {
		applog(LOG_ERR, "Cell name '%s' is invalid", chunkd_srv.cell);
		exit(1);
	}

	if (chunkd_srv.nid == 0) {	/* We have no NID, it's fatal */
#if 0 /* Not having NID is made non-fatal, because of CLD-less applications */
		if (!ctx.badnid) {	/* NID is missing (not invalid) */
			applog(LOG_ERR, "No NID configured");
		}
		exit(1);
#else
		if (ctx.badnid)
			exit(1);
		if (debugging)
			applog(LOG_DEBUG, "No NID configured");
#endif
	}

	free(ctx.geo_area);
	free(ctx.geo_zone);
	free(ctx.geo_rack);
}


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
	sprintf(str, "%lu\n", (unsigned long) getpid());
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

static struct {
	char		*text;
	bool		in_ssl;
	bool		in_listen;
	bool		have_ssl;
	char		*vol_path;
	struct listen_cfg tmp_listen;
} cfg_context;

static void cfg_elm_text (GMarkupParseContext *context,
			  const gchar	*text,
			  gsize		text_len,  
			  gpointer	user_data,
			  GError	**error)
{
	free(cfg_context.text);
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

		chunkd_srv.data_dir = cfg_context.text;
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

	if (!chunkd_srv.data_dir) {
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

	if (!chunkd_srv.listeners) {
		syslog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}
}

char *time2str(char *strbuf, time_t time)
{
	struct tm *tm = gmtime(&time);
	strftime(strbuf, 64, "%a, %d %b %Y %H:%M:%S %z", tm);
	return strbuf;
}

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen)
{
	int len = 0;

	if (!s)
		return 0;

	while ((len < maxlen) && (*s)) {
		s++;
		len++;
	}

	return len;
}
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
	struct sigaction osa, sa;
	int fd;
	pid_t newgrp;
	int oerrno;
	int osa_ok;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = sigaction(SIGHUP, &sa, &osa);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		exit(0);
	}

	newgrp = setsid();
	oerrno = errno;
	if (osa_ok != -1)
		sigaction(SIGHUP, &osa, NULL);

	if (newgrp == -1) {
		errno = oerrno;
		return (-1);
	}

	if (!nochdir)
		(void)chdir("/");

	if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}
	return (0);
}
#endif


#include "chunkd-config.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <argp.h>
#include <fcntl.h>
#include <poll.h>
#include <locale.h>
#include <stdarg.h>
#include <ctype.h>
#include <glib.h>
#include <chunk_msg.h>
#include <chunkc.h>

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max verbose)" },
	{ "config", 'c', "FILE", 0,
	  "Load key=value configuration file" },
	{ "host", 'h', "HOST:PORT", 0,
	  "Connect to remote chunkd at specified HOST:PORT" },
	{ "key", 'k', "FILE", 0,
	  "Read key from FILE, rather than command line" },
	{ "output", 'o', "FILE", 0,
	  "Send GET output to FILE, rather than stdout" },
	{ "ssl", 'S', NULL, 0,
	  "Enable SSL channel security" },
	{ "user", 'u', "USER", 0,
	  "Set username to USER" },
	{ "verbose", 'v', NULL, 0,
	  "Enable verbose libchunkdc output" },

	{ "list-cmds", 1001, NULL, 0,
	  "List supported commands" },

	{ }
};

static const char doc[] =
"chcli - command line interface to chunk data obj service";

static const char args_doc[] =
"COMMAND [ARG...]";

enum {
	GET_BUFSZ	= 16 * 1024,
};

enum chcli_cmd {
	CHC_NONE,
	CHC_GET,
	CHC_PUT,
};

struct chcli_host {
	char		*name;
	unsigned int	port;
};

static int debugging;
static GList *host_list;
static struct chcli_host *host;
static char username[CHD_USER_SZ + 1] = "";
static char *password;
static char *output_fn;
static char *key_data;
static gsize key_data_len;
static char *password_env = "CHCLI_PASSWORD";
static bool chcli_verbose;
static bool use_ssl;
static enum chcli_cmd cmd_mode = CHC_NONE;
static char **cmd_args;
static int n_cmd_args;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, args_doc, doc };

static bool push_host(const char *arg)
{
	char *colon;
	unsigned int port;
	struct chcli_host *dr;

	dr = malloc(sizeof(*dr));
	if (!dr) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, sizeof(*dr));
		goto err;
	}
	memset(dr, 0, sizeof(*dr));

	dr->name = strdup(arg);
	if (!dr->name) {
		fprintf(stderr, "%s: OOM (%zu)\n",
			__func__, strlen(arg));
		goto err_out;
	}

	colon = strrchr(dr->name, ':');
	if (!colon) {
		fprintf(stderr, "no port in host specifier `%s'\n", dr->name);
		goto err_out_host;
	}

	if (sscanf(colon, ":%u", &port) != 1) {
		fprintf(stderr, "port `%s' is invalid\n", colon+1);
		goto err_out_host;
	}
	if (port < 1 || port > 65535) {
		fprintf(stderr, "port `%s' is out of range\n", colon+1);
		goto err_out_host;
	}

	dr->port = port;

	*colon = 0;

	host_list = g_list_append(host_list, dr);

	return true;

err_out_host:
	free(dr->name);
err_out:
	free(dr);
err:
	return false;
}

static void show_cmds(void)
{
	fprintf(stderr,
"Supported chcli commands:\n"
"\n"
"GET key		Retrieve key, send to output (def: stdout)\n"
"PUT key val	Store key\n"
"\n"
		);

	exit(0);
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 'c': {
		char *s;
		GKeyFile *config;

		config = g_key_file_new();
		if (!config)
			return 1;

		if (!g_key_file_load_from_file(config, arg, 0, NULL)) {
			fprintf(stderr, "failed to read config file %s\n", arg);
			argp_usage(state);
		}

		s = g_key_file_get_string(config, "global", "host", NULL);
		if (s) {
			if (!push_host(s)) {
				fprintf(stderr, "invalid config host %s\n", s);
				argp_usage(state);
			}

			free(s);
		}

		s = g_key_file_get_string(config, "global", "username", NULL);
		if (s) {
			if ((!*s) || (strlen(s) >= CHD_USER_SZ)) {
				fprintf(stderr, "invalid config user %s\n", s);
				argp_usage(state);
			}

			strcpy(username, s);
			free(s);
		}

		password = g_key_file_get_string(config, "global", "password",
						 NULL);

		chcli_verbose = g_key_file_get_boolean(config, "global",
						       "verbose", NULL);
		use_ssl = g_key_file_get_boolean(config, "global", "ssl", NULL);

		debugging = g_key_file_get_integer(config, "global", "debug",
						   NULL);
		if (debugging < 0 || debugging > 2) {
			fprintf(stderr, "invalid config debug %d\n", debugging);
			argp_usage(state);
		}

		g_key_file_free(config);

		break;
	}

	case 'D':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			debugging = atoi(arg);
		else {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		if (!push_host(arg))
			argp_usage(state);
		break;
	case 'u':
		if (strlen(arg) >= CHD_USER_SZ) {
			fprintf(stderr, "invalid user: '%s'\n", arg);
			argp_usage(state);
		} else
			strcpy(username, arg);
		break;
	case 'k':
		if (!g_file_get_contents(arg, &key_data, &key_data_len,
					 NULL)) {
			fprintf(stderr, "failed to read key file %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'o':
		output_fn = arg;
		break;
	case 'v':
		chcli_verbose = true;
		break;
	case 'S':
		use_ssl = true;
		break;

	case 1001:			/* --list-cmds */
		show_cmds();
		break;

	case ARGP_KEY_ARG:
		if (cmd_mode != CHC_NONE)
			return ARGP_ERR_UNKNOWN; /* let next case parse it */

		if (!strcasecmp(arg, "get"))
			cmd_mode = CHC_GET;
		else if (!strcasecmp(arg, "put"))
			cmd_mode = CHC_PUT;
		else
			argp_usage(state);	/* invalid cmd */
		break;
	case ARGP_KEY_ARGS:
		cmd_args = state->argv + state->next;
		n_cmd_args = state->argc - state->next;
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int cmd_put(void)
{
	struct st_client *stc;

	/* if key data not supplied via file, absorb first cmd arg */
	if (!key_data) {
		if (!n_cmd_args) {
			fprintf(stderr, "PUT requires key arg\n");
			return 1;
		}

		key_data = cmd_args[0];
		key_data_len = strlen(cmd_args[0]) + 1;

		cmd_args++;
		n_cmd_args--;
	}

	if (n_cmd_args != 1) {
		fprintf(stderr, "PUT requires value arg\n");
		return 1;
	}

	if (key_data_len < 1 || key_data_len > CHD_KEY_SZ) {
		fprintf(stderr, "PUT: invalid key size %u\n",
			(unsigned int) key_data_len);
		return 1;
	}

	stc = stc_new(host->name, host->port, username, password, use_ssl);
	if (!stc) {
		fprintf(stderr, "%s:%u: failed to connect to storage\n",
			host->name,
			host->port);
		return 1;
	}

	stc->verbose = chcli_verbose;

	if (!stc_put_inline(stc, key_data, key_data_len,
			    cmd_args[0], strlen(cmd_args[0]), 0)) {
		fprintf(stderr, "PUT failed\n");
		return 1;
	}

	stc_free(stc);

	return 0;
}

static uint64_t get_len;
static char get_buf[GET_BUFSZ];

static bool recv_buf(struct st_client *stc, int rfd, void *buf, size_t buf_len)
{
	int rcvd;
	fd_set rset;
	int rc;

	/*
	 * This is a trick. We must check if SSL library had something
	 * prebuffered first, or else select may hang forever.
	 */
	rcvd = 0;
	for (;;) {
		rc = stc_get_recv(stc, buf + rcvd, buf_len);
		if (rc < 0)
			return false;

		rcvd += rc;
		buf_len -= rc;

		if (buf_len == 0)
			break;

		FD_ZERO(&rset);
		FD_SET(rfd, &rset);
		rc = select(rfd + 1, &rset, NULL, NULL, NULL);
		if (rc < 0)
			return false;

		assert(FD_ISSET(rfd, &rset));
	}
	return true;
}

static int cmd_get(void)
{
	struct st_client *stc;
	int rfd = -1, wfd;

	/* if key data not supplied via file, absorb first cmd arg */
	if (!key_data) {
		if (!n_cmd_args) {
			fprintf(stderr, "GET requires key arg\n");
			return 1;
		}

		key_data = cmd_args[0];
		key_data_len = strlen(cmd_args[0]) + 1;

		cmd_args++;
		n_cmd_args--;
	}

	if (key_data_len < 1 || key_data_len > CHD_KEY_SZ) {
		fprintf(stderr, "PUT: invalid key size %u\n",
			(unsigned int) key_data_len);
		return 1;
	}

	stc = stc_new(host->name, host->port, username, password, use_ssl);
	if (!stc) {
		fprintf(stderr, "%s:%u: failed to connect to storage\n",
			host->name,
			host->port);
		return 1;
	}

	stc->verbose = chcli_verbose;

	if (!stc_get_start(stc, key_data, key_data_len, &rfd, &get_len)) {
		fprintf(stderr, "GET initiation failed\n");
		return 1;
	}

	if (!output_fn || !strcmp(output_fn, "-"))
		wfd = STDOUT_FILENO;
	else {
		wfd = open(output_fn, O_CREAT | O_TRUNC | O_WRONLY, 0666);
		if (wfd < 0) {
			fprintf(stderr, "GET output file %s open failed: %s\n",
				output_fn,
				strerror(errno));
			return 1;
		}
	}

	while (get_len > 0) {
		size_t need_len;

		need_len = MIN(GET_BUFSZ, get_len);

		if (!recv_buf(stc, rfd, get_buf, need_len)) {
			fprintf(stderr, "GET buffer failed\n");
			return 1;
		}

		if (write(wfd, get_buf, need_len) != need_len) {
			fprintf(stderr, "GET write to output failed: %s\n",
				strerror(errno));
			unlink(output_fn);
			return 1;
		}

		get_len -= need_len;
	}

	if (wfd != STDOUT_FILENO)
		close(wfd);

	stc_free(stc);

	return 0;
}

int main (int argc, char *argv[])
{
	error_t aprc;

	setlocale(LC_ALL, "");

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if (!host_list) {
		fprintf(stderr, "no host specified\n");
		return 1;
	}

	if (strlen(username) == 0) {
		fprintf(stderr, "no username specified\n");
		return 1;
	}

	if (!password)
		password = getenv(password_env);
	if (!password) {
		fprintf(stderr, "no password found in env variable '%s'\n",
			password_env);
		return 1;
	}

	stc_init();

	host = host_list->data;

	switch (cmd_mode) {
	case CHC_NONE:
		return 1;
	case CHC_GET:
		return cmd_get();
	case CHC_PUT:
		return cmd_put();
	}

	return 0;
}


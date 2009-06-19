
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
#include "cld-config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <glib.h>
#include "cldb.h"

#define NAME "cldbadm"

enum various_modes {
	mode_check = 1,
	mode_create,
	mode_list_all,
};

struct {
	enum various_modes	mode;
	const char		*data_dir;

	struct cldb		cldb;
} cld_adm = {
	.data_dir		= "/spare/tmp/cld/lib",
};

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "all", 'a', NULL, 0,
	  "Output all lists (from database, to stdout)" },
	{ "check", 'c', NULL, 0,
	  "Check the database environment" },
	{ "create", 'C', NULL, 0,
	  "Create database environment" },
	{ "data", 'd', "DIRECTORY", 0,
	  "Store database environment in DIRECTORY" },
	{ }
};

static const char doc[] = NAME " - coarse locking database administration";

void do_list_locks(void);
static error_t parse_opt(int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

int main(int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr,
			NAME ": argp_parse failed: %s\n", strerror(aprc));
		exit(1);
	}

	cld_adm.cldb.home = cld_adm.data_dir;
	if (cldb_open(&cld_adm.cldb, DB_RECOVER, 0, "cldbadm", false))
		goto err_dbopen;

	switch (cld_adm.mode) {
	case mode_list_all:
		do_list_locks();
		break;
	case mode_create:
		fprintf(stderr, NAME ": Create (-C) is not implemented\n");
		fprintf(stderr, NAME ": Daemon creates its database as needed\n");
		goto err_act;
	case mode_check:
		fprintf(stderr, NAME ": Check (-c) is not implemented\n");
		goto err_act;
	default:
		fprintf(stderr, NAME ": internal error 1\n");
		goto err_act;
	}

	rc = 0;

 err_act:
	cldb_close(&cld_adm.cldb);
 err_dbopen:
	return rc;
}

void do_list_locks()
{
	printf("boo\n");
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'a':
		cld_adm.mode = mode_list_all;
		break;
	case 'c':
		cld_adm.mode = mode_check;
		break;
	case 'C':
		cld_adm.mode = mode_create;
		break;
	case 'd':
		cld_adm.data_dir = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/*
 * Stubs for contents of cldb.c
 */
int cldb_open(struct cldb *cldb, unsigned int env_flags, unsigned int flags,
	     const char *errpfx, bool do_syslog)
{

	return 0;
}

void cldb_close(struct cldb *cldb)
{
}

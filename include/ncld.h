#ifndef __NCLD_H__
#define __NCLD_H__

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
/*
 * The ncld.h API is a replacement for cldc.h. Do not include both.
 *
 * We do not believe into making "internal" structures "opaque"
 * with pointers to void. Therefore, this header might want include
 * some legacy definitions or whatnot, but users do not need to.
 */
#include <stdbool.h>
#include <glib.h>
#include <cldc.h>

struct ncld_sess {
	char			*host;
	unsigned short		port;
	GMutex			*mutex;
	GCond			*cond;
	GThread			*thread;
	bool			is_up;
	int			errc;
	GList			*handles;
	int			to_thread[2];
	struct cldc_udp		*udp;
	struct cld_timer	udp_timer;
	struct cld_timer_list	tlist;
	void			(*event)(void *, unsigned int);
	void			*event_arg;
};

struct ncld_fh {
	struct ncld_sess	*ses;
	struct cldc_fh		*fh;	/* FIXME cldc_open2 take direct & */
	bool			is_open;
	int			errc;
	int			nios;
	unsigned int		event_mask;
	void			(*event_func)(void *, unsigned int);
	void			*event_arg;
};

struct ncld_read {
	/* public to application */
	const void	*ptr;
	long		length;

	struct cldc_node_metadata meta;

	struct ncld_fh	*fh;
	/* GCond	*cond; -- abusing conditional of file handle for now */
	bool		is_done;
	int		errc;
};

extern struct ncld_sess *ncld_sess_open(const char *host, int port,
	int *error, void (*event)(void *, unsigned int), void *ev_arg,
	const char *cld_user, const char *cld_key);
extern struct ncld_fh *ncld_open(struct ncld_sess *s, const char *fname,
	unsigned int mode, int *error, unsigned int events,
	void (*event)(void *, unsigned int), void *ev_arg);
extern int ncld_del(struct ncld_sess *nsp, const char *fname);
extern struct ncld_read *ncld_get(struct ncld_fh *fhp, int *error);
extern struct ncld_read *ncld_get_meta(struct ncld_fh *fh, int *error);
extern void ncld_read_free(struct ncld_read *rp);
extern int ncld_write(struct ncld_fh *, const void *data, long len);
extern int ncld_trylock(struct ncld_fh *);
extern int ncld_qlock(struct ncld_fh *);
extern int ncld_unlock(struct ncld_fh *);
extern void ncld_close(struct ncld_fh *);
extern void ncld_sess_close(struct ncld_sess *s);
extern void ncld_init(void);

#endif /* __NCLD_H__ */

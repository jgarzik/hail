
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

#include <glib.h>
#include <cldc.h>
#include <cld_common.h>

static gint cld_timer_cmp(gconstpointer a_, gconstpointer b_)
{
	const struct cld_timer *a = a_;
	const struct cld_timer *b = b_;

	if (a->expires > b->expires)
		return 1;
	if (a->expires == b->expires)
		return 0;
	return -1;
}

void cld_timer_add(struct cld_timer_list *tlist, struct cld_timer *timer,
		   time_t expires)
{
	GList *timer_list = tlist->list;

	if (timer->on_list)
		timer_list = g_list_remove(timer_list, timer);

	/*
	 * This additional resiliency is required by the invocations from
	 * session_retry(). For some reason the computations in it result
	 * in attempts to add timers in the past sometimes, and then we loop
	 * when trying to run those. FIXME: maybe fix that one day.
	 *
	 * Even if we fix the callers, we probably should keep this.
	 */
	if (expires < tlist->runmark + 1)
		expires = tlist->runmark + 1;

	timer->on_list = true;
	timer->fired = false;
	timer->expires = expires;

	tlist->list = g_list_insert_sorted(timer_list, timer, cld_timer_cmp);
}

void cld_timer_del(struct cld_timer_list *tlist, struct cld_timer *timer)
{
	if (!timer->on_list)
		return;

	tlist->list = g_list_remove(tlist->list, timer);

	timer->on_list = false;
}

time_t cld_timers_run(struct cld_timer_list *tlist)
{
	struct cld_timer *timer;
	time_t now = time(NULL);
	time_t next_timeout = 0;
	GList *cur;

	tlist->runmark = now;
	for (;;) {
		cur = tlist->list;
		if (!cur)
			break;
		timer = cur->data;
		if (timer->expires > now)
			break;

		tlist->list = g_list_delete_link(tlist->list, cur);
		timer->on_list = false;

		timer->fired = true;
		timer->cb(timer);
	}

	if (tlist->list) {
		timer = tlist->list->data;
		if (timer->expires > now)
			next_timeout = (timer->expires - now);
		else
			next_timeout = 1;
	}

	return next_timeout;
}


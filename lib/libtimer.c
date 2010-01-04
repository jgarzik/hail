
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
#include <libtimer.h>

static GList *timer_list;

static gint timer_cmp(gconstpointer a_, gconstpointer b_)
{
	const struct timer *a = a_;
	const struct timer *b = b_;

	if (a->expires > b->expires)
		return 1;
	if (a->expires == b->expires)
		return 0;
	return -1;
}

void timer_add(struct timer *timer, time_t expires)
{
	if (timer->on_list)
		timer_list = g_list_remove(timer_list, timer);

	timer->on_list = true;
	timer->fired = false;
	timer->expires = expires;

	timer_list = g_list_insert_sorted(timer_list, timer, timer_cmp);
}

void timer_del(struct timer *timer)
{
	if (!timer->on_list)
		return;

	timer_list = g_list_remove(timer_list, timer);

	timer->on_list = false;
}

time_t timers_run(void)
{
	struct timer *timer;
	time_t now = time(NULL);
	time_t next_timeout = 0;
	GList *tmp, *cur;
	GList *exec_list = NULL;

	tmp = timer_list;
	while (tmp) {
		timer = tmp->data;
		cur = tmp;
		tmp = tmp->next;

		if (timer->expires > now)
			break;

		timer_list = g_list_remove_link(timer_list, cur);
		exec_list = g_list_concat(exec_list, cur);

		timer->on_list = false;
	}

	tmp = exec_list;
	while (tmp) {
		timer = tmp->data;
		tmp = tmp->next;

		timer->fired = true;
		timer->cb(timer);
	}

	if (timer_list) {
		timer = timer_list->data;
		if (timer->expires > now)
			next_timeout = (timer->expires - now);
		else
			next_timeout = 1;
	}

	return next_timeout;
}

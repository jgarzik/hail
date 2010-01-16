
#ifndef __LIBTIMER_H__
#define __LIBTIMER_H__

#include <stdbool.h>
#include <string.h>
#include <time.h>

struct cld_timer_list {
	void *list;
};

struct cld_timer {
	bool			fired;
	bool			on_list;
	void			(*cb)(struct cld_timer *);
	void			*userdata;
	time_t			expires;
	char			name[32];
};

extern void cld_timer_add(struct cld_timer_list *tlist, struct cld_timer *timer,
			  time_t expires);
extern void cld_timer_del(struct cld_timer_list *tlist, struct cld_timer *timer);
extern time_t cld_timers_run(struct cld_timer_list *tlist);

static inline void cld_timer_init(struct cld_timer *timer, const char *name,
	void (*cb)(struct cld_timer *), void *userdata)
{
	memset(timer, 0, sizeof(*timer));
	timer->cb = cb;
	timer->userdata = userdata;
	strncpy(timer->name, name, sizeof(timer->name));
	timer->name[sizeof(timer->name) - 1] = 0;
}

#endif /* __LIBTIMER_H__ */


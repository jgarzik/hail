
#ifndef __LIBTIMER_H__
#define __LIBTIMER_H__

#include <stdbool.h>
#include <string.h>
#include <time.h>

struct timer {
	bool			fired;
	bool			on_list;
	void			(*cb)(struct timer *);
	void			*userdata;
	time_t			expires;
	char			name[32];
};

extern void timer_add(struct timer *timer, time_t expires);
extern void timer_del(struct timer *timer);
extern time_t timers_run(void);

static inline void timer_init(struct timer *timer, const char *name,
			      void (*cb)(struct timer *), void *userdata)
{
	memset(timer, 0, sizeof(*timer));
	timer->cb = cb;
	timer->userdata = userdata;
	strncpy(timer->name, name, sizeof(timer->name));
	timer->name[sizeof(timer->name) - 1] = 0;
}

#endif /* __LIBTIMER_H__ */


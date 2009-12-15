#ifndef __HAIL_LOG_H__
#define __HAIL_LOG_H__

#include <stdbool.h>

struct hail_log {
	void (*func)(int prio, const char *fmt, ...);
	bool verbose;
};

/** Print out a debug message if 'verbose' is enabled */
#define HAIL_DEBUG(log, ...) \
	if ((log)->verbose) { \
		(log)->func(LOG_DEBUG, __VA_ARGS__); \
	}

/** Print out an informational log message */
#define HAIL_INFO(log, ...) \
	(log)->func(LOG_INFO, __VA_ARGS__);

/** Print out a warning message */
#define HAIL_WARN(log, ...) \
	(log)->func(LOG_WARNING, __VA_ARGS__);

/** Print out an error message */
#define HAIL_ERR(log, ...) \
	(log)->func(LOG_ERR, __VA_ARGS__);

/** Print out a critical warning message */
#define HAIL_CRIT(log, ...) \
	(log)->func(LOG_CRIT, __VA_ARGS__);

#endif /* __HAIL_LOG_H__ */

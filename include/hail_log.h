#ifndef __HAIL_LOG_H__
#define __HAIL_LOG_H__

#include <stdbool.h>

#ifdef __GNUC__
#define ATTR_PRINTF(x,y) __attribute__((format(printf, x, y)))
#else
#define ATTR_PRINTF(x,y)
#endif

struct hail_log {
	void (*func)(int prio, const char *fmt, ...) ATTR_PRINTF(2,3);
	bool debug;		/* unmutes HAIL_DEBUG */
	bool verbose;		/* enables CLD session verbosity */
};

/** Print out a CLD session debug message if enabled */
#define HAIL_VERBOSE(log, ...) \
	if ((log)->verbose) { \
		(log)->func(LOG_DEBUG, __VA_ARGS__); \
	}

/** Print out an application debug message if enabled */
#define HAIL_DEBUG(log, ...) \
	if ((log)->debug) { \
		(log)->func(LOG_DEBUG, __VA_ARGS__); \
	}

/** Print out an informational log message */
#define HAIL_INFO(log, ...) \
	(log)->func(LOG_INFO, __VA_ARGS__)

/** Print out a warning message */
#define HAIL_WARN(log, ...) \
	(log)->func(LOG_WARNING, __VA_ARGS__)

/** Print out an error message */
#define HAIL_ERR(log, ...) \
	(log)->func(LOG_ERR, __VA_ARGS__)

/** Print out a critical warning message */
#define HAIL_CRIT(log, ...) \
	(log)->func(LOG_CRIT, __VA_ARGS__)

#endif /* __HAIL_LOG_H__ */

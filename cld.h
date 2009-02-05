#ifndef __CLD_H__
#define __CLD_H__

#include <sys/epoll.h>
#include <netinet/in.h>
#include <glib.h>
#include "cldb.h"

struct client;
struct server_socket;

enum {
	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

enum server_poll_type {
	spt_udp,				/* UDP socket */
};

struct server_poll {
	enum server_poll_type	poll_type;	/* spt_xxx above */
	union {
		struct server_socket	*sock;
	} u;
};

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	struct server_poll	poll;		/* poll info */
	struct epoll_event	evt;		/* epoll info */
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		max_evt;	/* epoll events max'd out */
};

struct server_socket {
	int			fd;
	struct server_poll	poll;
	struct epoll_event	evt;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*data_dir;	/* database/log dir */
	char			*pid_file;	/* PID file */

	char			*port;		/* bind port */

	int			epoll_fd;	/* epoll descriptor */

	struct cldb		cldb;		/* database info */

	GList			*sockets;

	struct server_stats	stats;		/* global statistics */
};

/* server.c */
extern struct server cld_srv;
extern int debugging;

/* util.c */
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);

#endif /* __CLD_H__ */

#define _GNU_SOURCE
#include "chunkd-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>
#include "chunkd.h"

static GList *timer_list;

size_t strlist_len(GList *l)
{
	GList *tmp = l;
	size_t sum = 0;

	while (tmp) {
		sum += strlen(tmp->data);
		tmp = tmp->next;
	}

	return sum;
}

void __strlist_free(GList *l)
{
	GList *tmp = l;

	while (tmp) {
		free(tmp->data);
		tmp->data = NULL;
		tmp = tmp->next;
	}
}

void strlist_free(GList *l)
{
	__strlist_free(l);
	g_list_free(l);
}

void syslogerr(const char *prefix)
{
	applog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

void strup(char *s)
{
	while (*s) {
		*s = toupper(*s);
		s++;
	}
}

int write_pid_file(const char *pid_fn)
{
	char str[32], *s;
	size_t bytes;
	int fd;
	struct flock lock;
	int err;

	/* build file data */
	sprintf(str, "%u\n", (unsigned int) getpid());

	/* open non-exclusively (works on NFS v2) */
	fd = open(pid_fn, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err = errno;
		applog(LOG_ERR, "Cannot open PID file %s: %s",
		       pid_fn, strerror(err));
		return -err;
	}

	/* lock */
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lock) != 0) {
		err = errno;
		if (err == EAGAIN) {
			applog(LOG_ERR, "PID file %s is already locked",
			       pid_fn);
		} else {
			applog(LOG_ERR, "Cannot lock PID file %s: %s",
			       pid_fn, strerror(err));
		}
		close(fd);
		return -err;
	}

	/* write file data */
	bytes = strlen(str);
	s = str;
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			err = errno;
			applog(LOG_ERR, "PID number write failed: %s",
			       strerror(err));
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if (fsync(fd) < 0) {
		err = errno;
		applog(LOG_ERR, "PID file fsync failed: %s", strerror(err));
		goto err_out;
	}

	return fd;

err_out:
	unlink(pid_fn);
	close(fd);
	return -err;
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		rc = errno;
		applog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(rc));
		return -rc;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			rc = errno;
			applog(LOG_ERR, "%s F_SETFL: %s", prefix, strerror(rc));
			rc = -rc;
		}

	return rc;
}

void hexstr(const unsigned char *buf, size_t buf_len, char *outstr)
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < buf_len; i++) {
		outstr[i * 2]       = hex[(buf[i] & 0xF0) >> 4];
		outstr[(i * 2) + 1] = hex[(buf[i] & 0x0F)     ];
	}

	outstr[buf_len * 2] = 0;
}

char *time2str(char *strbuf, time_t src_time)
{
	struct tm *tm = gmtime(&src_time);
	strftime(strbuf, 64, "%a, %d %b %Y %H:%M:%S %z", tm);
	return strbuf;
}

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
	if (timer->on_list) {
		timer_list = g_list_remove(timer_list, timer);

		if (debugging)
			applog(LOG_WARNING, "BUG? timer %s added twice "
			       "(expires: old %llu, new %llu)",
			       timer->name,
			       (unsigned long long) timer->expires,
			       (unsigned long long) expires);
	}

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

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen)
{
	int len = 0;

	if (!s)
		return 0;

	while ((len < maxlen) && (*s)) {
		s++;
		len++;
	}

	return len;
}
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
	struct sigaction osa, sa;
	int fd;
	pid_t newgrp;
	int oerrno;
	int osa_ok;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = sigaction(SIGHUP, &sa, &osa);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		exit(0);
	}

	newgrp = setsid();
	oerrno = errno;
	if (osa_ok != -1)
		sigaction(SIGHUP, &osa, NULL);

	if (newgrp == -1) {
		errno = oerrno;
		return (-1);
	}

	if (!nochdir)
		(void)chdir("/");

	if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}
	return (0);
}
#endif

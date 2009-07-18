
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
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cldc.h>

void cldc_udp_free(struct cldc_udp *udp)
{
	if (!udp)
		return;

	if (udp->fd >= 0)
		close(udp->fd);

	free(udp);
}

static void cldc_udp_timer(int fd, short events, void *userdata)
{
	struct cldc_udp *udp = userdata;

	if (udp->cb)
		udp->cb(udp->sess, udp->cb_private);
}

int cldc_udp_new(const char *hostname, int port,
		 struct cldc_udp **udp_out)
{
	struct cldc_udp *udp;
	struct addrinfo hints, *res, *rp;
	char port_s[32];
	int rc, fd = -1;

	*udp_out = NULL;

	sprintf(port_s, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	rc = getaddrinfo(hostname, port_s, &hints, &res);
	if (rc)
		return -ENOENT;

	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* success */

		close(fd);
		fd = -1;
	}

	if (!rp) {
		freeaddrinfo(res);
		return -ENOENT;
	}

	udp = calloc(1, sizeof(*udp));
	if (!udp) {
		freeaddrinfo(res);
		close(fd);
		return -ENOMEM;
	}

	memcpy(udp->addr, rp->ai_addr, rp->ai_addrlen);
	udp->addr_len = rp->ai_addrlen;

	udp->fd = fd;

	evtimer_set(&udp->timer_ev, cldc_udp_timer, udp);

	freeaddrinfo(res);

	*udp_out = udp;

	return 0;
}

int cldc_udp_receive_pkt(struct cldc_udp *udp)
{
	char buf[2048];
	ssize_t rc, crc;

	rc = recv(udp->fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (rc < 0) {
		if (errno != EAGAIN)
			return -errno;
	}
	if (rc <= 0)
		return 0;

	if (!udp->sess)
		return -ENXIO;

	crc = cldc_receive_pkt(udp->sess, udp->addr, udp->addr_len, buf, rc);
	if (crc)
		return crc;

	return 0;
}

int cldc_udp_pkt_send(void *private,
			const void *addr, size_t addrlen,
			const void *buf, size_t buflen)
{
	struct cldc_udp *udp = private;
	ssize_t rc;

	/* we are connected, so we ignore addr and addrlen args */
	rc = send(udp->fd, buf, buflen, MSG_DONTWAIT);
	if (rc < 0)
		return -errno;
	if (rc != buflen)
		return -EILSEQ;

	return 0;
}

bool cldc_levent_timer(void *private, bool add,
		       int (*cb)(struct cldc_session *, void *),
		       void *cb_private,
		       time_t secs)
{
	struct cldc_udp *udp = private;
	struct timeval tv = { secs, 0 };

	if (add) {
		udp->cb = cb;
		udp->cb_private = cb_private;
		return evtimer_add(&udp->timer_ev, &tv) == 0;
	} else {
		return evtimer_del(&udp->timer_ev) == 0;
	}
}


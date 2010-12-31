
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
#include "hail-config.h"

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

void cldc_tcp_free(struct cldc_tcp *tcp)
{
	if (!tcp)
		return;

	if (tcp->fd >= 0)
		close(tcp->fd);

	free(tcp);
}

int cldc_tcp_new(const char *hostname, int port,
		 struct cldc_tcp **tcp_out)
{
	struct cldc_tcp *tcp;
	struct addrinfo hints, *res, *rp;
	char port_s[32];
	int rc, fd = -1;

	*tcp_out = NULL;

	sprintf(port_s, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

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

	tcp = calloc(1, sizeof(*tcp));
	if (!tcp) {
		freeaddrinfo(res);
		close(fd);
		return -ENOMEM;
	}

	memcpy(tcp->addr, rp->ai_addr, rp->ai_addrlen);
	tcp->addr_len = rp->ai_addrlen;

	tcp->fd = fd;

	freeaddrinfo(res);

	*tcp_out = tcp;

	return 0;
}

int cldc_tcp_receive_pkt_data(struct cldc_tcp *tcp)
{
	static char buf[CLD_RAW_MSG_SZ];	/* BUG: static buf */
	ssize_t rc, crc;
	void *p;

	if (tcp->ubbp_read < sizeof(tcp->ubbp)) {
		p = &tcp->ubbp;
		p += tcp->ubbp_read;
		rc = read(tcp->fd, p, sizeof(tcp->ubbp) - tcp->ubbp_read);
		if (rc < 0) {
			if (errno != EAGAIN)
				return -errno;
			return 0;
		}

		tcp->ubbp_read += rc;
		if (tcp->ubbp_read == sizeof(tcp->ubbp)) {
#ifdef WORDS_BIGENDIAN
			swab32(ubbp.op_size);
#endif

			if (memcmp(tcp->ubbp.magic, "CLD1", 4))
				return -EIO;
			if (UBBP_OP(tcp->ubbp.op_size) != 2)
				return -EIO;
			tcp->raw_read = 0;
			tcp->raw_size = UBBP_SIZE(tcp->ubbp.op_size);
			if (tcp->raw_size > CLD_RAW_MSG_SZ)
				return -EIO;
		}
	}
	if (!tcp->raw_size)
		return 0;

	p = buf;		/* BUG: uses temp buffer */
	p += tcp->raw_read;
	rc = read(tcp->fd, p, tcp->raw_size - tcp->raw_read);
	if (rc < 0) {
		if (errno != EAGAIN)
			return -errno;
		return 0;
	}

	tcp->raw_read += rc;

	if (tcp->raw_read < tcp->raw_size)
		return 0;

	tcp->ubbp_read = 0;

	crc = cldc_receive_pkt(tcp->sess, tcp->addr, tcp->addr_len, buf,
				tcp->raw_size);
	if (crc)
		return crc;

	return 0;
}

int cldc_tcp_pkt_send(void *private,
			const void *addr, size_t addrlen,
			const void *buf, size_t buflen)
{
	struct cldc_tcp *tcp = private;
	ssize_t rc;
	struct ubbp_header ubbp;

	memcpy(ubbp.magic, "CLD1", 4);
	ubbp.op_size = (buflen << 8) | 1;
#ifdef WORDS_BIGENDIAN
	swab32(ubbp.op_size);
#endif

	rc = write(tcp->fd, &ubbp, sizeof(ubbp));
	if (rc < 0)
		return -errno;

	rc = write(tcp->fd, buf, buflen);
	if (rc < 0)
		return -errno;

	return 0;
}



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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <syslog.h>
#include "cldc.h"

#define ADDRSIZE	24	/* Enough for IPv6, including port. */

/*
 * Helper: Look up the host to verify it, then save the parameters into
 * our struct (*hp). This way the application quits early if DNS is set wrong.
 */
int cldc_saveaddr(struct cldc_host *hp,
			 unsigned int priority,
			 unsigned int weight, unsigned int port,
			 unsigned int nlen, const char *name,
			 struct hail_log *log)
{
	char portstr[11];
	char *hostname;
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	bool something_suitable;
	int rc;

	sprintf(portstr, "%u", port);

	hostname = malloc(nlen + 1);
	if (!hostname) {
		rc = -ENOMEM;
		goto err_name;
	}
	memcpy(hostname, name, nlen);
	hostname[nlen] = 0;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(hostname, portstr, &hints, &res0);
	if (rc) {
		rc = -(rc + 1200);
		goto err_addr;
	}

	something_suitable = false;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		something_suitable = true;
		break;
	}

	if (!something_suitable) {
		rc = -1031;
		goto err_suitable;
	}

	hp->host = hostname;
	hp->port = port;
	hp->prio = priority;
	hp->weight = weight;

	freeaddrinfo(res0);
	return 0;

err_suitable:
	freeaddrinfo(res0);
err_addr:
	free(hostname);
err_name:
	return rc;
}

/*
 * Apparently, the only viable way to find out the DNS domain is to take
 * the hostname, then lop off the first member. We do not support running
 * on YP-driven networks with nonqualified hostnames (at least for now).
 */
static int cldc_make_fqdn(char *buf, int size, const char *srvname,
			  const char *thishost)
{
	char *s;
	int nlen;
	int dlen;

	nlen = strlen(srvname);
	if (nlen >= (size - 20))
		return -1;

	if (thishost == NULL)
		return -1;
	if ((s = strchr(thishost, '.')) == NULL)
		return -1;
	s++;

	dlen = strlen(s);
	if (nlen + 1 + dlen + 1 > size)
		return -1;

	memcpy(buf, srvname, nlen);
	buf[nlen] = '.';
	strcpy(buf + nlen + 1, s);

	return 0;
}

static void push_host(GList **host_list, struct cldc_host *hp_in)
{
	struct cldc_host *hp;

	hp = malloc(sizeof(*hp));
	if (!hp)
		/* FIXME: OOM squawk */
		return;

	memcpy(hp, hp_in, sizeof(*hp));

	*host_list = g_list_append(*host_list, hp);
}

/*
 * Fill out host list, based on DNS lookups.
 * This is not reentrant.  Better be called before any other threads
 * are started.
 */
int cldc_getaddr(GList **host_list, const char *thishost, struct hail_log *log)
{
	enum { hostsz = 64 };
	char cldb[hostsz];
	unsigned char resp[512];
	int rlen;
	ns_msg nsb;
	ns_rr rrb;
	int rrlen;
	char hostb[hostsz];
	int i;
	struct cldc_host hp;
	const unsigned char *p;
	int rc;
	int search_retries = 10;

	/*
	 * We must create FQDN or else the first thing the resolver does
	 * is a lookup in the DNS root (probably the standard-compliant
	 * dot between "_cld" and "_udp" hurts us here).
	 */
	if (cldc_make_fqdn(cldb, hostsz, "_cld._udp", thishost) != 0) {
		HAIL_INFO(log, "internal error in cldc_make_fqdn(%s)",
			  thishost);
		return -1;
	}

do_try_again:
	rc = res_search(cldb, ns_c_in, ns_t_srv, resp, 512);
	if (rc < 0) {
		switch (h_errno) {
		case HOST_NOT_FOUND:
			HAIL_INFO(log, "%s: No _cld._udp SRV record", __func__);
			return -1;
		case NO_DATA:
			HAIL_INFO(log, "%s: Cannot find _cld._udp"
				  " SRV record", __func__);
			return -1;
		case TRY_AGAIN:
			if (search_retries-- > 0)
				goto do_try_again;
			/* fall through */
		case NO_RECOVERY:
		default:
			HAIL_ERR(log, "%s: res_search error (%d): %s",
				 __func__, h_errno, hstrerror(h_errno));
			return -1;
		}
	}
	rlen = rc;

	if (rlen == 0) {
		HAIL_INFO(log, "%s: res_search returned empty reply", __func__);
		return -1;
	}

	if (ns_initparse(resp, rlen, &nsb) < 0) {
		HAIL_ERR(log, "%s: ns_initparse error", __func__);
		return -1;
	}

	for (i = 0; i < ns_msg_count(nsb, ns_s_an); i++) {
		rc = ns_parserr(&nsb, ns_s_an, i, &rrb);
		if (rc < 0)
			continue;

		if (ns_rr_class(rrb) != ns_c_in)
			continue;

		memset(&hp, 0, sizeof(hp));

		switch (ns_rr_type(rrb)) {
		case ns_t_srv:
			rrlen = ns_rr_rdlen(rrb);
			if (rrlen < 8) {	/* 2+2+2 and 2 for host */
				HAIL_DEBUG(log, "%s: SRV len %d",
					   __func__, rrlen);
				break;
			}
			p = ns_rr_rdata(rrb);
			rc = dn_expand(resp, resp+rlen, p+6, hostb, hostsz);
			if (rc < 0) {
				HAIL_DEBUG(log, "%s: dn_expand error %d",
					   __func__, rc);
				break;
			}
			if (rc < 2) {
				HAIL_DEBUG(log, "%s: dn_expand short %d",
					   __func__, rc);
				break;
			}

			if (cldc_saveaddr(&hp, ns_get16(p+0),
					  ns_get16(p+2), ns_get16(p+4),
					  rc, hostb, NULL))
				break;

			HAIL_DEBUG(log, "%s: found CLD host %s port %u"
				   " prio %d weight %d",
				   __func__, hp.host, hp.port,
				   hp.prio, hp.weight);

			push_host(host_list, &hp);
			break;
		case ns_t_cname:	/* impossible, but */
			HAIL_DEBUG(log, "%s: CNAME in SRV request, ignored",
				   __func__);
			break;
		default:
			;
		}
	}

	return 0;
}


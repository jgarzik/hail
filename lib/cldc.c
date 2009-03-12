
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include "cldc.h"

static unsigned int next_msgid;

int cldc_init(void)
{
	srand(time(NULL) ^ getpid());

	next_msgid = rand();

	return 0;
}

void cldc_free(struct cld_client *cldc)
{
	if (!cldc)
		return;

	if (cldc->fd >= 0)
		close(cldc->fd);
	
	memset(cldc, 0, sizeof(*cldc));
	free(cldc);
}

struct cld_client *cldc_new(const char *remote_host, int remote_port,
			    int local_port)
{
	struct cld_client *cldc;
	struct addrinfo hints, *res = NULL, *tr;
	int rc;
	char port_str[32];

	sprintf(port_str, "%d", local_port);

	cldc = calloc(1, sizeof(*cldc));
	if (!cldc)
		return NULL;

	cldc->fd = -1;
	cldc->local_port = local_port;
	strncpy(cldc->host, remote_host, sizeof(cldc->host));
	cldc->host[sizeof(cldc->host) - 1] = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, port_str, &hints, &res);
	if (rc)
		goto err_out;

	/* we just use the first successful result, for now */

	for (tr = res; tr != NULL; tr = tr->ai_next) {
		cldc->fd = socket(tr->ai_family, tr->ai_socktype,
				  tr->ai_protocol);
		if (cldc->fd < 0)
			continue;

		if (bind(cldc->fd, tr->ai_addr, tr->ai_addrlen) == 0)
			break;

		close(cldc->fd);
		cldc->fd = -1;
	}

	if (cldc->fd < 0)
		goto err_out_res;

	memcpy(&cldc->local_addr, tr->ai_addr, tr->ai_addrlen);
	cldc->local_addrlen = tr->ai_addrlen;

	freeaddrinfo(res);

	if (fcntl(cldc->fd, F_SETFL, O_NONBLOCK) < 0)
		goto err_out;

	sprintf(port_str, "%d", remote_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	res = NULL;

	rc = getaddrinfo(cldc->host, port_str, &hints, &res);
	if (rc)
		goto err_out;

	memcpy(&cldc->addr, res->ai_addr, res->ai_addrlen);
	cldc->addrlen = res->ai_addrlen;

	freeaddrinfo(res);

	return cldc;

err_out_res:
	freeaddrinfo(res);
err_out:
	free(cldc);
	return NULL;
}


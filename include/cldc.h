#ifndef __CLDC_H__
#define __CLDC_H__

struct cld_client {
	int			fd;		/* UDP socket */

	char			host[256];
	struct sockaddr_in6	addr;
	socklen_t		addrlen;

	struct sockaddr_in6	local_addr;
	socklen_t		local_addrlen;
	int			local_port;
};

extern int cldc_init(void);
extern void cldc_free(struct cld_client *cldc);
extern struct cld_client *cldc_new(const char *remote_host, int remote_port,
				   int local_port);

#endif /* __CLDC_H__ */

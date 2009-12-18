
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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <locale.h>
#include <argp.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cld-private.h>
#include "cld.h"

#define PROGRAM_NAME "cld"

#define CLD_DEF_PORT	"8081"
#define CLD_DEF_PIDFN	CLD_LOCAL_STATE_DIR "/run/cld.pid"
#define CLD_DEF_DATADIR	CLD_LIBDIR "/cld/lib"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLD_RAW_MSG_SZ		= 4096,
};

static struct argp_option options[] = {
	{ "data", 'd', "DIRECTORY", 0,
	  "Store database environment in DIRECTORY.  Default: "
	  CLD_DEF_DATADIR },
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max)" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "port", 'p', "PORT", 0,
	  "Bind to UDP port PORT.  Default: " CLD_DEF_PORT },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE.  Default: " CLD_DEF_PIDFN },
	{ "strict-free", 1001, NULL, 0,
	  "For memory-checker runs.  When shutting down server, free local "
	  "heap, rather than simply exit(2)ing and letting OS clean up." },
	{ "port-file", 1002, "FILE", 0,
	  "Write the listen port to FILE." },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - coarse locking daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
static bool use_syslog = true;
static bool strict_free = false;
struct timeval current_time;

struct server cld_srv = {
	.data_dir		= CLD_DEF_DATADIR,
	.pid_file		= CLD_DEF_PIDFN,
	.port			= CLD_DEF_PORT,
};

static void ensure_root(void);

static void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (use_syslog) {
		vsyslog(prio, fmt, ap);
	} else {
		char *f;
		int len;
		int pid;

		pid = getpid() & 0xFFFFFFFF;
		len = sizeof(PROGRAM_NAME "[0123456789]: ") + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, PROGRAM_NAME "[%u]: %s\n", pid, fmt);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
	}
	va_end(ap);
}

struct hail_log srv_log = {
	.func = applog,
	.verbose = 0,
};

int udp_tx(int sock_fd, struct sockaddr *addr, socklen_t addr_len,
	   const void *data, size_t data_len)
{
	ssize_t src;

	HAIL_DEBUG(&srv_log, "udp_tx, fd %d", sock_fd);

	src = sendto(sock_fd, data, data_len, 0, addr, addr_len);
	if (src < 0 && errno != EAGAIN)
		applog(LOG_ERR, "udp_tx sendto (fd %d, data_len %u): %s",
		       sock_fd, (unsigned int) data_len,
		       strerror(errno));

	if (src < 0)
		return -errno;

	return 0;
}

void resp_copy(struct cld_msg_resp *resp, const struct cld_msg_hdr *src)
{
	memcpy(&resp->hdr, src, sizeof(*src));
	resp->code = 0;
	resp->rsv = 0;
	resp->xid_in = src->xid;
}

void resp_err(struct session *sess,
	      const struct cld_msg_hdr *src, enum cle_err_codes errcode)
{
	struct cld_msg_resp resp;

	resp_copy(&resp, src);
	__cld_rand64(&resp.hdr.xid);
	resp.code = cpu_to_le32(errcode);

	if (sess->sock_fd <= 0) {
		applog(LOG_ERR, "Nul sock in response");
		return;
	}

	sess_sendmsg(sess, &resp, sizeof(resp), NULL, NULL);
}

void resp_ok(struct session *sess, const struct cld_msg_hdr *src)
{
	resp_err(sess, src, CLE_OK);
}

static const char *user_key(const char *user)
{
	/* TODO: better auth scheme.
	 * for now, use simple username==password auth scheme
	 */
	if (!user || !*user ||
	    (strnlen(user, 32) >= 32))
		return NULL;

	return user;	/* our secret key */
}

static bool authcheck(const struct cld_packet *pkt, size_t pkt_len)
{
	const char *key;
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned int md_len = 0;
	const void *p = pkt;

	key = user_key(pkt->user);
	if (!key)
		return false;

	HMAC(EVP_sha1(), key, strlen(key), p, pkt_len - SHA_DIGEST_LENGTH,
	     md, &md_len);

	if (md_len != SHA_DIGEST_LENGTH)
		return false; /* BUG */

	if (memcmp(md, p + (pkt_len - SHA_DIGEST_LENGTH), SHA_DIGEST_LENGTH))
		return false;

	return true;
}

bool authsign(struct cld_packet *pkt, size_t pkt_len)
{
	const char *key;
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned int md_len = 0;
	void *buf = pkt;

	key = user_key(pkt->user);
	if (!key)
		return false;

	HMAC(EVP_sha1(), key, strlen(key), buf, pkt_len - SHA_DIGEST_LENGTH,
	     md, &md_len);

	if (md_len != SHA_DIGEST_LENGTH)
		applog(LOG_ERR, "authsign BUG: md_len != SHA_DIGEST_LENGTH");

	memcpy(buf + pkt_len - SHA_DIGEST_LENGTH, md, SHA_DIGEST_LENGTH);

	return true;
}

const char *opstr(enum cld_msg_ops op)
{
	switch (op) {
	case cmo_nop:		return "cmo_nop";
	case cmo_new_sess:	return "cmo_new_sess";
	case cmo_open:		return "cmo_open";
	case cmo_get_meta:	return "cmo_get_meta";
	case cmo_get:		return "cmo_get";
	case cmo_put:		return "cmo_put";
	case cmo_close:		return "cmo_close";
	case cmo_del:		return "cmo_del";
	case cmo_lock:		return "cmo_lock";
	case cmo_unlock:	return "cmo_unlock";
	case cmo_trylock:	return "cmo_trylock";
	case cmo_ack:		return "cmo_ack";
	case cmo_end_sess:	return "cmo_end_sess";
	case cmo_ping:		return "cmo_ping";
	case cmo_not_master:	return "cmo_not_master";
	case cmo_event:		return "cmo_event";
	case cmo_ack_frag:	return "cmo_ack_frag";
	default:		return "(unknown)";
	}
}

static void show_msg(const struct cld_msg_hdr *msg)
{
	switch (msg->op) {
	case cmo_nop:
	case cmo_new_sess:
	case cmo_open:
	case cmo_get_meta:
	case cmo_get:
	case cmo_put:
	case cmo_close:
	case cmo_del:
	case cmo_lock:
	case cmo_unlock:
	case cmo_trylock:
	case cmo_ack:
	case cmo_end_sess:
	case cmo_ping:
	case cmo_not_master:
	case cmo_event:
	case cmo_ack_frag:
		HAIL_DEBUG(&srv_log, "msg: op %s, xid %llu",
		       opstr(msg->op),
		       (unsigned long long) le64_to_cpu(msg->xid));
		break;
	}
}

static void udp_rx_msg(const struct client *cli, const struct cld_packet *pkt,
		       const struct cld_msg_hdr *msg, struct msg_params *mp)
{
	struct session *sess = mp->sess;

	if (srv_log.verbose)
		show_msg(msg);

	switch(msg->op) {
	case cmo_nop:
		resp_ok(sess, msg);
		break;

	case cmo_new_sess:	msg_new_sess(mp, cli); break;
	case cmo_end_sess:	msg_end_sess(mp, cli); break;
	case cmo_open:		msg_open(mp); break;
	case cmo_get:		msg_get(mp, false); break;
	case cmo_get_meta:	msg_get(mp, true); break;
	case cmo_put:		msg_put(mp); break;
	case cmo_close:		msg_close(mp); break;
	case cmo_del:		msg_del(mp); break;
	case cmo_unlock:	msg_unlock(mp); break;
	case cmo_lock:		msg_lock(mp, true); break;
	case cmo_trylock:	msg_lock(mp, false); break;
	case cmo_ack:		msg_ack(mp); break;

	default:
		/* do nothing */
		break;
	}
}

static void pkt_ack_frag(int sock_fd,
			 const struct client *cli,
			 const struct cld_packet *pkt)
{
	size_t alloc_len;
	struct cld_packet *outpkt;
	struct cld_msg_ack_frag *ack_msg;

	alloc_len = sizeof(*outpkt) + sizeof(*ack_msg) + SHA_DIGEST_LENGTH;
	outpkt = alloca(alloc_len);
	ack_msg = (struct cld_msg_ack_frag *) (outpkt + 1);
	memset(outpkt, 0, alloc_len);

	pkt_init_pkt(outpkt, pkt);

	memcpy(ack_msg->hdr.magic, CLD_MSG_MAGIC, CLD_MAGIC_SZ);
	__cld_rand64(&ack_msg->hdr.xid);
	ack_msg->hdr.op = cmo_ack_frag;
	ack_msg->seqid = pkt->seqid;

	authsign(outpkt, alloc_len);

	HAIL_DEBUG(&srv_log, "ack-partial-msg: "
		"sid " SIDFMT ", op %s, seqid %llu",
		SIDARG(outpkt->sid), opstr(ack_msg->hdr.op),
		(unsigned long long) le64_to_cpu(outpkt->seqid));

	/* transmit ack-partial-msg response (once, without retries) */
	udp_tx(sock_fd, (struct sockaddr *) &cli->addr, cli->addr_len,
	       outpkt, alloc_len);
}

static void udp_rx(int sock_fd,
		   const struct client *cli,
		   const void *raw_pkt, size_t pkt_len)
{
	const struct cld_packet *pkt = raw_pkt;
	struct cld_packet *outpkt;
	const struct cld_msg_hdr *msg = (struct cld_msg_hdr *) (pkt + 1);
	struct session *sess = NULL;
	enum cle_err_codes resp_rc = CLE_OK;
	struct cld_msg_resp *resp;
	struct msg_params mp;
	size_t alloc_len;
	uint32_t pkt_flags;
	bool first_frag, last_frag, have_new_sess, have_ack, have_put;

	/* verify pkt data integrity and credentials via HMAC signature */
	if (!authcheck(pkt, pkt_len)) {
		resp_rc = CLE_SIG_INVAL;
		goto err_out;
	}

	pkt_flags = le32_to_cpu(pkt->flags);
	first_frag = pkt_flags & CPF_FIRST;
	last_frag = pkt_flags & CPF_LAST;
	have_new_sess = first_frag && (msg->op == cmo_new_sess);
	have_ack = first_frag && (msg->op == cmo_ack);
	have_put = first_frag && (msg->op == cmo_put);

	/* look up client session, verify it matches IP and username */
	sess = g_hash_table_lookup(cld_srv.sessions, pkt->sid);
	if (sess &&
	    ((sess->addr_len != cli->addr_len) ||
	     memcmp(&sess->addr, &cli->addr, sess->addr_len) ||
	     strncmp(pkt->user, sess->user, CLD_MAX_USERNAME) ||
	     sess->dead)) {
		resp_rc = CLE_SESS_INVAL;
		goto err_out;
	}

	mp.sock_fd = sock_fd;
	mp.cli = cli;
	mp.sess = sess;
	mp.pkt = pkt;
	mp.msg = msg;
	mp.msg_len = pkt_len - sizeof(*pkt) - SHA_DIGEST_LENGTH;

	HAIL_DEBUG(&srv_log, "pkt: len %zu, seqid %llu, sid " SIDFMT ", "
		"flags %s%s, user %s",
		pkt_len, (unsigned long long) le64_to_cpu(pkt->seqid),
		SIDARG(pkt->sid),
		first_frag ? "F" : "", last_frag ? "L" : "",
		pkt->user);

	/* advance sequence id's and update last-contact timestamp */
	if (!have_new_sess) {
		if (!sess) {
			resp_rc = CLE_SESS_INVAL;
			goto err_out;
		}

		sess->last_contact = current_time.tv_sec;
		sess->sock_fd = sock_fd;

		if (!have_ack) {
			/* eliminate duplicates; do not return any response */
			if (le64_to_cpu(pkt->seqid) != sess->next_seqid_in) {
				HAIL_DEBUG(&srv_log, "dropping dup");
				return;
			}

			/* received message - update session */
			sess->next_seqid_in++;
		}
	} else {
		if (sess) {
			/* eliminate duplicates; do not return any response */
			if (le64_to_cpu(pkt->seqid) != sess->next_seqid_in) {
				HAIL_DEBUG(&srv_log, "dropping dup");
				return;
			}

			resp_rc = CLE_SESS_EXISTS;
			goto err_out;
		}
	}

	/* copy message fragment into reassembly buffer */
	if (sess) {
		if (first_frag)
			sess->msg_buf_len = 0;

		if ((sess->msg_buf_len + mp.msg_len) > CLD_MAX_MSG_SZ) {
			resp_rc = CLE_BAD_PKT;
			goto err_out;
		}

		memcpy(&sess->msg_buf[sess->msg_buf_len], msg, mp.msg_len);
		sess->msg_buf_len += mp.msg_len;

		if (!last_frag) {
			pkt_ack_frag(sock_fd, cli, pkt);
			return;
		}

		mp.msg = msg = (struct cld_msg_hdr *) sess->msg_buf;
		mp.msg_len = sess->msg_buf_len;

		if ((srv_log.verbose > 1) && !first_frag)
			HAIL_DEBUG(&srv_log, "    final message size %u",
			       sess->msg_buf_len);
	}

	if (last_frag)
		udp_rx_msg(cli, pkt, msg, &mp);
	return;

err_out:
	/* transmit error response (once, without retries) */
	alloc_len = sizeof(*outpkt) + sizeof(*resp) + SHA_DIGEST_LENGTH;
	outpkt = alloca(alloc_len);
	resp = (struct cld_msg_resp *) (outpkt + 1);
	memset(outpkt, 0, alloc_len);

	pkt_init_pkt(outpkt, pkt);

	resp_copy(resp, msg);
	resp->code = cpu_to_le32(resp_rc);

	authsign(outpkt, alloc_len);

	HAIL_DEBUG(&srv_log, "udp_rx err: "
		"sid " SIDFMT ", op %s, seqid %llu, code %d",
		SIDARG(outpkt->sid), opstr(resp->hdr.op),
		(unsigned long long) le64_to_cpu(outpkt->seqid),
		resp_rc);

	udp_tx(sock_fd, (struct sockaddr *) &cli->addr, cli->addr_len,
	       outpkt, alloc_len);
}

static bool udp_srv_event(int fd, short events, void *userdata)
{
	struct client cli;
	char host[64];
	ssize_t rrc;
	struct msghdr hdr;
	struct iovec iov[2];
	uint8_t raw_pkt[CLD_RAW_MSG_SZ], ctl_msg[CLD_RAW_MSG_SZ];
	struct cld_packet *pkt = (struct cld_packet *) raw_pkt;

	memset(&cli, 0, sizeof(cli));

	iov[0].iov_base = raw_pkt;
	iov[0].iov_len = sizeof(raw_pkt);

	hdr.msg_name = &cli.addr;
	hdr.msg_namelen = sizeof(cli.addr);
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = ctl_msg;
	hdr.msg_controllen = sizeof(ctl_msg);

	rrc = recvmsg(fd, &hdr, 0);
	if (rrc < 0) {
		syslogerr("UDP recvmsg");
		return true; /* continue main loop; do NOT terminate server */
	}
	cli.addr_len = hdr.msg_namelen;

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli.addr, cli.addr_len,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;

	strcpy(cli.addr_host, host);

	HAIL_DEBUG(&srv_log, "client %s message (%d bytes)", host, (int) rrc);

	/* if it is complete garbage, drop immediately */
	if ((rrc < (sizeof(*pkt) + SHA_DIGEST_LENGTH)) ||
	    (memcmp(pkt->magic, CLD_PKT_MAGIC, sizeof(pkt->magic)))) {
		cld_srv.stats.garbage++;
		return true; /* continue main loop; do NOT terminate server */
	}

	if (cld_srv.cldb.is_master && cld_srv.cldb.up)
		udp_rx(fd, &cli, raw_pkt, rrc);

	else {
		struct cld_packet *outpkt;
		struct cld_msg_hdr *msg = (struct cld_msg_hdr *) (pkt + 1);
		struct cld_msg_resp *resp;
		size_t alloc_len;

		alloc_len = sizeof(*outpkt) + sizeof(*resp) + SHA_DIGEST_LENGTH;
		outpkt = alloca(alloc_len);
		memset(outpkt, 0, alloc_len);

		pkt_init_pkt(outpkt, pkt);

		/* transmit not-master error msg */
		resp = (struct cld_msg_resp *) (outpkt + 1);
		resp_copy(resp, msg);
		resp->hdr.op = cmo_not_master;

		authsign(outpkt, alloc_len);

		udp_tx(fd, (struct sockaddr *) &cli.addr, cli.addr_len,
		       outpkt, alloc_len);
	}

	return true;	/* continue main loop; do NOT terminate server */
}

static void add_chkpt_timer(void)
{
	timer_add(&cld_srv.chkpt_timer, time(NULL) + CLD_CHKPT_SEC);
}

static void cldb_checkpoint(struct timer *timer)
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	int rc;

	gettimeofday(&current_time, NULL);

	HAIL_DEBUG(&srv_log, "db4 checkpoint");

	/* flush logs to db, if log files >= 1MB */
	rc = dbenv->txn_checkpoint(dbenv, 1024, 0, 0);
	if (rc)
		dbenv->err(dbenv, rc, "txn_checkpoint");

	/* reactivate timer, to call ourselves again */
	add_chkpt_timer();
}

static int net_write_port(const char *port_file, const char *port_str)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s\n", port_str);
	fclose(portf);
	return 0;
}

static void net_close(void)
{
	struct pollfd *pfd;
	int i;

	if (!cld_srv.polls)
		return;

	for (i = 0; i < cld_srv.polls->len; i++) {
		pfd = &g_array_index(cld_srv.polls, struct pollfd, i);
		if (pfd->fd >= 0) {
			if (close(pfd->fd) < 0)
				applog(LOG_WARNING, "net_close(%d): %s",
				       pfd->fd, strerror(errno));
			pfd->fd = -1;
		}
	}
}

static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_poll sp;
	struct pollfd pfd;
	int fd, rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		syslogerr("udp socket");
		return -errno;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		syslogerr("udp bind");
		close(fd);
		return -errno;
	}

	rc = fsetflags("udp server", fd, O_NONBLOCK);
	if (rc) {
		close(fd);
		return -errno;
	}

	sp.fd = fd;
	sp.cb = udp_srv_event;
	sp.userdata = NULL;
	g_array_append_val(cld_srv.poll_data, sp);

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	g_array_append_val(cld_srv.polls, pfd);

	return fd;
}

static int net_open_any(void)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int fd4, fd6;
	socklen_t addr_len;
	unsigned short port;
	int rc;

	port = 0;

	/* Thanks to Linux, IPv6 must be bound first. */
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	memcpy(&addr6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
	fd6 = net_open_socket(AF_INET6, SOCK_DGRAM, 0, sizeof(addr6), &addr6);

	if (fd6 >= 0) {
		addr_len = sizeof(addr6);
		if (getsockname(fd6, (struct sockaddr *) &addr6,
				&addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr6.sin6_port);
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	/* If IPv6 worked, we must use the same port number for IPv4 */
	if (port)
		addr4.sin_port = port;
	fd4 = net_open_socket(AF_INET, SOCK_DGRAM, 0, sizeof(addr4), &addr4);

	if (!port) {
		if (fd4 < 0)
			return fd4;

		addr_len = sizeof(addr4);
		if (getsockname(fd4, (struct sockaddr *) &addr4,
				&addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr4.sin_port);
	}

	applog(LOG_INFO, "Listening on port %u", port);

	if (cld_srv.port_file) {
		char portstr[7];
		snprintf(portstr, sizeof(portstr), "%u\n", port);
		return net_write_port(cld_srv.port_file, portstr);
	}
	return 0;
}

static int net_open_known(const char *portstr)
{
	int ipv6_found = 0;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, portstr, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       portstr, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

#ifdef __linux__
	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}
#endif

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(res->ai_family, res->ai_socktype,
				     res->ai_protocol,
				     res->ai_addrlen, res->ai_addr);
		if (rc < 0)
			goto err_out;

		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);

	if (cld_srv.port_file)
		return net_write_port(cld_srv.port_file, portstr);
	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static int net_open(void)
{
	if (!cld_srv.port)
		return net_open_any();
	else
		return net_open_known(cld_srv.port);
}

static void segv_signal(int signo)
{
	applog(LOG_ERR, "SIGSEGV");
	exit(1);
}

static void term_signal(int signo)
{
	server_running = false;
}

static void stats_signal(int signo)
{
	dump_stats = true;
}

#define X(stat) \
	applog(LOG_INFO, "STAT %s %lu", #stat, cld_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(garbage);
}

#undef X

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'd':
		cld_srv.data_dir = arg;
		break;
	case 'D':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			srv_log.verbose = atoi(arg);
		else {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 'E':
		use_syslog = false;
		break;
	case 'F':
		cld_srv.flags |= SFL_FOREGROUND;
		break;
	case 'p':
		/*
		 * We do not permit "0" as an argument in order to be safer
		 * against a malfunctioning jumpstart script or a simple
		 * misunderstanding by a human operator.
		 */
		if (!strcmp(arg, "auto")) {
			cld_srv.port = NULL;
		} else if (atoi(arg) > 0 && atoi(arg) < 65536) {
			cld_srv.port = arg;
		} else {
			fprintf(stderr, "invalid port: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		cld_srv.pid_file = arg;
		break;

	case 1001:			/* --strict-free */
		strict_free = true;
		break;
	case 1002:
		cld_srv.port_file = arg;
		break;

	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int main_loop(void)
{
	time_t next_timeout;

	next_timeout = timers_run();

	while (server_running) {
		struct pollfd *pfd;
		int i, fired, rc;

		cld_srv.stats.poll++;

		/* poll for fd activity, or next timer event */
		rc = poll(&g_array_index(cld_srv.polls, struct pollfd, 0),
			  cld_srv.polls->len,
			  next_timeout ? (next_timeout * 1000) : -1);
		if (rc < 0) {
			syslogerr("poll");
			if (errno != EINTR)
				break;
		}

		gettimeofday(&current_time, NULL);

		/* determine which fd's fired; call their callbacks */
		fired = 0;
		for (i = 0; i < cld_srv.polls->len; i++) {
			struct server_poll *sp;
			bool runrunrun;
			short revents;

			/* ref pollfd struct */
			pfd = &g_array_index(cld_srv.polls, struct pollfd, i);

			/* if no events fired, move on to next */
			if (!pfd->revents)
				continue;

			fired++;

			revents = pfd->revents;
			pfd->revents = 0;

			/* ref 1:1 matching server_poll struct */
			sp = &g_array_index(cld_srv.poll_data,
					    struct server_poll, i);

			cld_srv.stats.event++;

			/* call callback, shutting down server if requested */
			runrunrun = sp->cb(sp->fd, revents, sp->userdata);
			if (!runrunrun) {
				server_running = false;
				break;
			}

			/* if we reached poll(2) activity count, it is
			 * pointless to continue looping
			 */
			if (fired == rc)
				break;
		}

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}

		next_timeout = timers_run();
	}

	return 0;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	gettimeofday(&current_time, NULL);
	srand(current_time.tv_sec ^ getpid());

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * open syslog, background outselves, write PID file ASAP
	 */

	if (use_syslog)
		openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);

	if (!(cld_srv.flags & SFL_FOREGROUND) && (daemon(1, !use_syslog) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(cld_srv.pid_file);
	if (rc < 0)
		goto err_out;
	cld_srv.pid_fd = rc;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGSEGV, segv_signal);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	if (cldb_init(&cld_srv.cldb, cld_srv.data_dir, NULL,
		      DB_CREATE | DB_THREAD | DB_RECOVER,
		      "cld", use_syslog,
		      DB_CREATE | DB_THREAD, NULL))
		exit(1);

	ensure_root();

	timer_init(&cld_srv.chkpt_timer, "db4-checkpoint",
		   cldb_checkpoint, NULL);
	add_chkpt_timer();

	rc = 1;

	cld_srv.sessions = g_hash_table_new(sess_hash, sess_equal);
	cld_srv.timers = g_queue_new();
	cld_srv.poll_data = g_array_sized_new(FALSE, FALSE,
					   sizeof(struct server_poll), 4);
	cld_srv.polls = g_array_sized_new(FALSE,FALSE,sizeof(struct pollfd), 4);
	if (!cld_srv.sessions || !cld_srv.timers || !cld_srv.poll_data ||
	    !cld_srv.polls)
		goto err_out_pid;

	if (sess_load(cld_srv.sessions) != 0)
		goto err_out_pid;

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_pid;

	HAIL_INFO(&srv_log, "initialized: verbose %u%s",
	       srv_log.verbose,
	       strict_free ? ", strict-free" : "");

	/*
	 * execute main loop
	 */
	rc = main_loop();

	applog(LOG_INFO, "shutting down");

	if (strict_free)
		timer_del(&cld_srv.chkpt_timer);

	if (cld_srv.cldb.up)
		cldb_down(&cld_srv.cldb);
	cldb_fini(&cld_srv.cldb);

err_out_pid:
	unlink(cld_srv.pid_file);
	close(cld_srv.pid_fd);
err_out:
	if (strict_free) {
		net_close();
		g_array_free(cld_srv.polls, TRUE);
		g_array_free(cld_srv.poll_data, TRUE);
		g_queue_free(cld_srv.timers);
		sessions_free();
		g_hash_table_unref(cld_srv.sessions);
	}

	closelog();

	return rc;
}

/*
 * Check if root inode exists, create if not.
 */
static void ensure_root()
{
	DB_ENV *dbenv = cld_srv.cldb.env;
	DB_TXN *txn;
	struct raw_inode *inode;
	int rc;

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		exit(1);
	}

	rc = cldb_inode_get_byname(txn, "/", sizeof("/")-1, &inode, false, 0);
	if (rc == 0) {
		HAIL_DEBUG(&srv_log, "Root inode found, ino %llu",
			(unsigned long long) cldino_from_le(inode->inum));
	} else if (rc == DB_NOTFOUND) {
		inode = cldb_inode_mem("/", sizeof("/")-1, CIFL_DIR, CLD_INO_ROOT);
		if (!inode) {
			applog(LOG_CRIT, "Cannot allocate new root inode");
			goto err_;
		}

		inode->time_create =
		inode->time_modify = cpu_to_le64(current_time.tv_sec);
		inode->version = cpu_to_le32(1);

		rc = cldb_inode_put(txn, inode, 0);
		if (rc) {
			free(inode);
			applog(LOG_CRIT, "Cannot allocate new root inode");
			goto err_;
		}

		HAIL_DEBUG(&srv_log, "Root inode created, ino %llu",
			(unsigned long long) cldino_from_le(inode->inum));
		free(inode);
	} else {
		dbenv->err(dbenv, rc, "Root inode lookup");
		goto err_;
	}
	/* Might as well cache the inode here, maybe later */

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		exit(1);
	}
	return;

 err_:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	exit(1);
}



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
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cld-private.h>
#include "cld.h"

#define PROGRAM_NAME "cld"

#define CLD_DEF_PORT	"8081"
#define CLD_DEF_PIDFN	CLD_LOCAL_STATE_DIR "/run/cld.pid"
#define CLD_DEF_DATADIR	CLD_LIBDIR "/cld/lib"

const char *argp_program_version = PACKAGE_VERSION;

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
	  "Bind to TCP port PORT.  Default: " CLD_DEF_PORT },
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
static bool atcp_read(struct atcp_read_state *rst,
		      void *buf, unsigned int buf_size,
		      void (*cb)(void *, bool), void *cb_data);
static void cli_free(struct client *cli);
static void cli_rd_ubbp(void *userdata, bool success);

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
};

int tcp_tx(int sock_fd, struct sockaddr *addr, socklen_t addr_len,
	   const void *data, size_t data_len)
{
	ssize_t src;
	struct ubbp_header ubbp;

	memcpy(ubbp.magic, "CLD1", 4);
	ubbp.op_size = (data_len << 8) | 2;
#ifdef WORDS_BIGENDIAN
	swab32(ubbp.op_size);
#endif

	src = write(sock_fd, &ubbp, sizeof(ubbp));
	if (src < 0 && errno != EAGAIN)
		HAIL_ERR(&srv_log, "%s sendto (fd %d, data_len %u): %s",
			 __func__, sock_fd, (unsigned int) data_len,
			 strerror(errno));

	if (src < 0)
		return -errno;
	
	src = write(sock_fd, data, data_len);
	if (src < 0 && errno != EAGAIN)
		HAIL_ERR(&srv_log, "%s sendto (fd %d, data_len %u): %s",
			 __func__, sock_fd, (unsigned int) data_len,
			 strerror(errno));

	if (src < 0)
		return -errno;

	return 0;
}

const char *user_key(const char *user)
{
	/* TODO: better auth scheme.
	 * for now, use simple username==password auth scheme
	 */
	if (!user || !*user ||
	    (strnlen(user, 32) >= 32))
		return NULL;

	return user;	/* our secret key */
}

static int tcp_rx_handle(struct session *sess,
			 void (*msg_handler)(struct session *, const void *),
			 xdrproc_t xdrproc, void *xdrdata)
{
	XDR xin;

	xdrmem_create(&xin, sess->msg_buf, sess->msg_buf_len, XDR_DECODE);
	if (!xdrproc(&xin, xdrdata)) {
		HAIL_DEBUG(&srv_log, "%s: couldn't parse %s message",
			   __func__, cld_opstr(sess->msg_op));
		xdr_destroy(&xin);
		return CLE_BAD_PKT;
	}
	msg_handler(sess, xdrdata);
	xdr_free(xdrproc, xdrdata);
	xdr_destroy(&xin);
	return 0;
}

/** Recieve a TCP packet
 *
 * @param sock_fd	The TCP socket we received the packet on
 * @param cli		Client address data
 * @param info		Packet information
 * @param raw_pkt	The raw packet buffer
 * @param raw_len	Length of the raw packet buffer
 *
 * @return		An error code if we should send an error message
 *			response. CLE_OK if we are done.
 */
static enum cle_err_codes tcp_rx(int sock_fd, const struct client *cli,
				 struct pkt_info *info, const char *raw_pkt,
				 size_t raw_len)
{
	struct cld_pkt_hdr *pkt = info->pkt;
	struct session *sess = info->sess;

	if (sess) {
		size_t msg_len;

		/* advance sequence id's and update last-contact timestamp */
		sess->last_contact = current_time.tv_sec;
		sess->sock_fd = sock_fd;

		if (info->op != CMO_ACK) {
			/* received message - update session */
			sess->next_seqid_in++;
		}

		/* copy message fragment into reassembly buffer */
		if (pkt->mi.order & CLD_PKT_IS_FIRST) {
			sess->msg_op = info->op;
			sess->msg_xid = info->xid;
			sess->msg_buf_len = 0;
		}
		msg_len = raw_len - info->hdr_len - CLD_PKT_FTR_LEN;
		if ((sess->msg_buf_len + msg_len) > CLD_MAX_MSG_SZ)
			return CLE_BAD_PKT;

		memcpy(sess->msg_buf + sess->msg_buf_len,
			raw_pkt + info->hdr_len, msg_len);
		sess->msg_buf_len += msg_len;
	}

	if (!(pkt->mi.order & CLD_PKT_IS_LAST)) {
		struct cld_msg_ack_frag ack;
		ack.seqid = info->seqid;

		/* transmit ack-partial-msg response (once, without retries) */
		simple_sendmsg(sock_fd, cli, pkt->sid,
			       pkt->user, 0xdeadbeef,
			       (xdrproc_t)xdr_cld_msg_ack_frag, (void *)&ack,
			       CMO_ACK_FRAG);
		return CLE_OK;
	}

	/* Handle a complete message */
	switch (info->op) {
	case CMO_GET:
		/* fall through */
	case CMO_GET_META: {
		struct cld_msg_get get = {0};
		return tcp_rx_handle(sess, msg_get,
				     (xdrproc_t)xdr_cld_msg_get, &get);
	}
	case CMO_OPEN: {
		struct cld_msg_open open_msg = {0};
		return tcp_rx_handle(sess, msg_open,
				     (xdrproc_t)xdr_cld_msg_open, &open_msg);
	}
	case CMO_PUT: {
		struct cld_msg_put put = {0};
		return tcp_rx_handle(sess, msg_put,
				     (xdrproc_t)xdr_cld_msg_put, &put);
	}
	case CMO_CLOSE: {
		struct cld_msg_close close_msg = {0};
		return tcp_rx_handle(sess, msg_close,
				     (xdrproc_t)xdr_cld_msg_close, &close_msg);
	}
	case CMO_DEL: {
		struct cld_msg_del del = {0};
		return tcp_rx_handle(sess, msg_del,
				     (xdrproc_t)xdr_cld_msg_del, &del);
	}
	case CMO_UNLOCK: {
		struct cld_msg_unlock unlock = {0};
		return tcp_rx_handle(sess, msg_unlock,
				     (xdrproc_t)xdr_cld_msg_unlock, &unlock);
	}
	case CMO_TRYLOCK:
		/* fall through */
	case CMO_LOCK: {
		struct cld_msg_lock lock = {0};
		return tcp_rx_handle(sess, msg_lock,
				     (xdrproc_t)xdr_cld_msg_lock, &lock);
	}
	case CMO_ACK:
		msg_ack(sess, info->seqid);
		return 0;
	case CMO_NOP:
		sess_sendresp_generic(sess, CLE_OK);
		return 0;
	case CMO_NEW_SESS:
		msg_new_sess(sock_fd, cli, info);
		return 0;
	case CMO_END_SESS:
		msg_end_sess(sess, info->xid);
		return 0;
	default:
		HAIL_DEBUG(&srv_log, "%s: unexpected %s packet",
			   __func__, cld_opstr(info->op));
		/* do nothing */
		return 0;
	}
}

/** Parse a packet's header. Verify that the magic number is correct.
 *
 * @param raw_pkt	Pointer to the packet data
 * @param raw_len	Length of the raw data
 * @param pkt		(out param) the packet header
 * @param hdr_len	(out param) the length of the packet header
 *
 * @return		true on success; false if this packet is garbage
 */
static bool parse_pkt_header(const char *raw_pkt, int raw_len,
			     struct cld_pkt_hdr *pkt, ssize_t *hdr_len)
{
	XDR xin;
	static const char * const magic = CLD_PKT_MAGIC;

	if (raw_len <= CLD_PKT_FTR_LEN) {
		HAIL_DEBUG(&srv_log, "%s: packet is too short: only "
			   "%d bytes", __func__, raw_len);
		return false;
	}
	xdrmem_create(&xin, (void *)raw_pkt, raw_len - CLD_PKT_FTR_LEN,
		      XDR_DECODE);
	memset(pkt, 0, sizeof(*pkt));
	if (!xdr_cld_pkt_hdr(&xin, pkt)) {
		HAIL_DEBUG(&srv_log, "%s: couldn't parse packet header",
			   __func__);
		xdr_destroy(&xin);
		return false;
	}
	*hdr_len = xdr_getpos(&xin);
	xdr_destroy(&xin);

	if (memcmp((void *)&pkt->magic, magic, sizeof(pkt->magic))) {
		HAIL_DEBUG(&srv_log, "%s: bad magic number", __func__);
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)pkt);
		return false;
	}

	return true;
}

/** Look up some information about a packet, including its session and the
 * type of message it carries.
 *
 * @param pkt		The packet's header
 * @param raw_pkt	Pointer to the raw packet data
 * @param raw_len	Length of the raw packet data
 * @param info		(out param) Information about the packet
 *
 * @return		true on success; false if this packet is garbage
 */
static bool get_pkt_info(struct cld_pkt_hdr *pkt,
			 const char *raw_pkt, size_t raw_len,
			 size_t hdr_len, struct pkt_info *info)
{
	struct cld_pkt_ftr *foot;
	struct session *s;

	memset(info, 0, sizeof(*info));
	info->pkt = pkt;
	info->sess = s = g_hash_table_lookup(cld_srv.sessions, &pkt->sid);
	foot = (struct cld_pkt_ftr *)
			(raw_pkt + (raw_len - CLD_PKT_FTR_LEN));
	info->seqid = le64_to_cpu(foot->seqid);

	if (pkt->mi.order & CLD_PKT_IS_FIRST) {
		info->xid = pkt->mi.cld_pkt_msg_info_u.mi.xid;
		info->op = pkt->mi.cld_pkt_msg_info_u.mi.op;
	} else {
		if (!s) {
			HAIL_DEBUG(&srv_log, "%s: packet is not first, "
				"but also not part of an existing session. "
				"Protocol error.", __func__);
			return false;
		}
		info->xid = s->msg_xid;
		info->op = s->msg_op;
	}
	info->hdr_len = hdr_len;
	return true;
}

/** Verify that the client session matches IP and username
 *
 * @param info		Packet information
 * @param cli		Client address data
 *
 * @return		0 on success; error code otherwise
 */
static enum cle_err_codes validate_pkt_session(const struct pkt_info *info,
					       const struct client *cli)
{
	struct session *sess = info->sess;

	if (!sess) {
		/* Packets that don't belong to a session must be new-session
		 * packets attempting to establish a session. */
		if (info->op != CMO_NEW_SESS) {
			HAIL_DEBUG(&srv_log, "%s: packet doesn't belong to a "
				   "session,but has type %d",
				   __func__, info->op);
			return CLE_SESS_INVAL;
		}
		return 0;
	}

	if (info->op == CMO_NEW_SESS) {
		HAIL_DEBUG(&srv_log, "%s: Tried to create a new session, "
			   "but a session with that ID already exists.",
			   __func__);
		return CLE_SESS_EXISTS;
	}

	/* verify that client session matches IP */
	if ((sess->addr_len != cli->addr_len) ||
	     memcmp(&sess->addr, &cli->addr, sess->addr_len)) {
		HAIL_DEBUG(&srv_log, "%s: sess->addr doesn't match packet "
			   "addr", __func__);
		return CLE_SESS_INVAL;
	}

	/* verify that client session matches username */
	if (strncmp(info->pkt->user, sess->user, CLD_MAX_USERNAME)) {
		HAIL_DEBUG(&srv_log, "%s: session doesn't match packet's  "
			   "username", __func__);
		return CLE_SESS_INVAL;
	}

	if (sess->dead) {
		HAIL_DEBUG(&srv_log, "%s: packet session is dead",
			   __func__);
		return CLE_SESS_INVAL;
	}

	return 0;
}

/** Check a packet's cryptographic signature
 *
 * @param raw_pkt	Pointer to the packet data
 * @param raw_len	Length of the raw data
 * @param pkt		the packet header
 *
 * @return		0 on success; error code otherwise
 */
static enum cle_err_codes pkt_chk_sig(const char *raw_pkt, int raw_len,
				      const struct cld_pkt_hdr *pkt)
{
	struct cld_pkt_ftr *foot;
	const char *secret_key;
	int auth_rc;

	foot = (struct cld_pkt_ftr *)
			(raw_pkt + (raw_len - CLD_PKT_FTR_LEN));
	secret_key = user_key(pkt->user);

	auth_rc = cld_authcheck(&srv_log, secret_key, raw_pkt,
				  raw_len - SHA_DIGEST_LENGTH,
				  foot->sha);
	if (auth_rc) {
		HAIL_DEBUG(&srv_log, "auth failed, code %d", auth_rc);
		return CLE_SIG_INVAL;
	}

	return 0;
}

void simple_sendmsg(int fd, const struct client *cli,
		    uint64_t sid, const char *user, uint64_t seqid,
		    xdrproc_t xdrproc, const void *xdrdata, enum cld_msg_op op)
{
	XDR xhdr, xmsg;
	struct cld_pkt_hdr pkt;
	struct cld_pkt_msg_infos *infos;
	struct cld_pkt_ftr *foot;
	const char *secret_key;
	char *buf;
	size_t msg_len, hdr_len, buf_len;
	int auth_rc;

	/* Set up the packet header */
	memset(&pkt, 0, sizeof(cld_pkt_hdr));
	memcpy(&pkt.magic, CLD_PKT_MAGIC, sizeof(pkt.magic));
	pkt.sid = sid;
	pkt.user = (char *)user;
	pkt.mi.order = CLD_PKT_ORD_FIRST_LAST;
	infos = &pkt.mi.cld_pkt_msg_info_u.mi;
	cld_rand64(&infos->xid);
	infos->op = op;

	/* Determine sizes */
	msg_len = xdr_sizeof(xdrproc, (void *)xdrdata);
	if (msg_len > CLD_MAX_MSG_SZ) {
		HAIL_ERR(&srv_log, "%s: tried to put %zu message bytes in a "
			 "single packet. Maximum message bytes per packet "
			 "is %d", __func__, msg_len, CLD_MAX_PKT_MSG_SZ);
		return;
	}
	hdr_len = xdr_sizeof((xdrproc_t)xdr_cld_pkt_hdr, &pkt);
	buf_len = msg_len + hdr_len + CLD_PKT_FTR_LEN;
	buf = alloca(buf_len);

	/* Serialize data */
	xdrmem_create(&xhdr, buf, hdr_len, XDR_ENCODE);
	if (!xdr_cld_pkt_hdr(&xhdr, &pkt)) {
		xdr_destroy(&xhdr);
		HAIL_ERR(&srv_log, "%s: xdr_cld_pkt_hdr failed",
			 __func__);
		return;
	}
	xdr_destroy(&xhdr);
	xdrmem_create(&xmsg, buf + hdr_len, msg_len, XDR_ENCODE);
	if (!xdrproc(&xmsg, (void *)xdrdata)) {
		xdr_destroy(&xmsg);
		HAIL_ERR(&srv_log, "%s: xdrproc failed", __func__);
		return;
	}
	xdr_destroy(&xmsg);

	foot = (struct cld_pkt_ftr *)
		(buf + (buf_len - SHA_DIGEST_LENGTH));
	foot->seqid = cpu_to_le64(seqid);
	secret_key = user_key(user);

	auth_rc =cld_authsign(&srv_log, secret_key, buf,
				buf_len - SHA_DIGEST_LENGTH,
				foot->sha);
	if (auth_rc)
		HAIL_ERR(&srv_log, "%s: authsign failed: %d",
			 __func__, auth_rc);

	tcp_tx(fd, (struct sockaddr *) &cli->addr, cli->addr_len,
		buf, buf_len);
}

static void simple_sendresp(int sock_fd, const struct client *cli,
			    const struct pkt_info *info,
			    enum cle_err_codes code)
{
	const struct cld_pkt_hdr *pkt = info->pkt;
	struct cld_msg_generic_resp resp;
	resp.code = code;
	resp.xid_in = info->xid;

	simple_sendmsg(sock_fd, cli, pkt->sid, pkt->user, info->seqid,
		       (xdrproc_t)xdr_cld_msg_generic_resp, (void *)&resp,
		       info->op);
}

static void cli_rd_pkt(void *userdata, bool success)
{
	struct client *cli = userdata;
	int fd = cli->fd;
	ssize_t rrc, hdr_len;
	struct cld_pkt_hdr pkt;
	struct pkt_info info;
	enum cle_err_codes err;

	rrc = cli->raw_size;

	HAIL_DEBUG(&srv_log, "client %s message (%d bytes)",
		   cli->addr_host, (int) rrc);

	if (!parse_pkt_header(cli->raw_pkt, rrc, &pkt, &hdr_len)) {
		cld_srv.stats.garbage++;
		return;
	}

	if (!get_pkt_info(&pkt, cli->raw_pkt, rrc, hdr_len, &info)) {
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
		cld_srv.stats.garbage++;
		return;
	}

	err = validate_pkt_session(&info, cli);
	if (err) {
		simple_sendresp(fd, cli, &info, err);
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
		return;
	}

	err = pkt_chk_sig(cli->raw_pkt, rrc, &pkt);
	if (err) {
		simple_sendresp(fd, cli, &info, err);
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
		return;
	}

	if (!(cld_srv.cldb.is_master && cld_srv.cldb.up)) {
		simple_sendmsg(fd, cli, pkt.sid, pkt.user, 0xdeadbeef,
			       (xdrproc_t)xdr_void, NULL, CMO_NOT_MASTER);
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
		return;
	}

	err = tcp_rx(fd, cli, &info, cli->raw_pkt, rrc);
	if (err) {
		simple_sendresp(fd, cli, &info, err);
		xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
		return;
	}
	xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);

	atcp_read(&cli->rst, &cli->ubbp, sizeof(cli->ubbp),
		  cli_rd_ubbp, cli);
}

static void cli_rd_ubbp(void *userdata, bool success)
{
	struct client *cli = userdata;
	uint32_t sz;

#ifdef WORDS_BIGENDIAN
	swab32(cli->ubbp.op_size);
#endif
	if (memcmp(cli->ubbp.magic, "CLD1", 4))
		goto err_out;
	if (UBBP_OP(cli->ubbp.op_size) != 1)
		goto err_out;
	sz = UBBP_SIZE(cli->ubbp.op_size);
	if (sz > CLD_RAW_MSG_SZ)
		goto err_out;

	cli->raw_size = sz;

	atcp_read(&cli->rst, cli->raw_pkt, sz, cli_rd_pkt, cli);

	return;

err_out:
	cli_free(cli);
}

static void add_chkpt_timer(void)
{
	struct timeval tv = { .tv_sec = CLD_CHKPT_SEC };

	if (evtimer_add(&cld_srv.chkpt_timer, &tv) < 0)
		HAIL_WARN(&srv_log, "chkpt timer add failed");
}

static void cldb_checkpoint(int fd, short events, void *userdata)
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

static void atcp_read_init(struct atcp_read_state *rst)
{
	memset(rst, 0, sizeof(*rst));
	INIT_LIST_HEAD(&rst->q);
}

static bool atcp_read(struct atcp_read_state *rst,
		      void *buf, unsigned int buf_size,
		      void (*cb)(void *, bool), void *cb_data)
{
	struct atcp_read *rd;

	rd = calloc(1, sizeof(*rd));
	if (!rd)
		goto err_out;

	rd->buf = buf;
	rd->buf_size = buf_size;
	rd->bytes_wanted = buf_size;
	rd->cb = cb;
	rd->cb_data = cb_data;

	INIT_LIST_HEAD(&rd->node);

	list_add_tail(&rd->node, &rst->q);

	return true;

err_out:
	cb(cb_data, false);
	return false;
}

static bool atcp_read_event(struct atcp_read_state *rst, int fd)
{
	struct atcp_read *tmp, *iter;

	list_for_each_entry_safe(tmp, iter, &rst->q, node) {
		ssize_t rrc;

		rrc = read(fd, tmp->buf + tmp->bytes_read,
			   tmp->bytes_wanted);
		if (rrc < 0) {
			if (errno == EAGAIN)
				return true;
			return false;
		}
		if (rrc == 0)
			break;

		tmp->bytes_read += rrc;
		tmp->bytes_wanted -= rrc;

		if (tmp->bytes_read == tmp->buf_size) {
			list_del_init(&tmp->node);

			tmp->cb(tmp->cb_data, true);
			free(tmp);
		}
	}

	return true;
}

static struct client *cli_alloc(void)
{
	struct client *cli;

	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return NULL;

	cli->addr_len = sizeof(cli->addr);

	atcp_read_init(&cli->rst);
	
	return cli;
}

static void cli_free(struct client *cli)
{
	if (!cli)
		return;

	if (cli->fd >= 0) {
		event_del(&cli->ev);
		close(cli->fd);
		cli->fd = -1;
	}
	
	free(cli);
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	atcp_read_event(&cli->rst, fd);
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	struct client *cli;
	char host[64];
	char port[16];
	int on = 1;

	cli = cli_alloc();
	if (!cli) {
		applog(LOG_ERR, "out of memory");
		server_running = false;
		event_loopbreak();
		return;
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr,
			 &cli->addr_len);
	if (cli->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	event_set(&cli->ev, cli->fd, EV_READ | EV_PERSIST,
		  tcp_cli_event, cli);

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, cli->addr_len,
		    host, sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	host[sizeof(host) - 1] = 0;
	port[sizeof(port) - 1] = 0;
	applog(LOG_INFO, "client host %s port %s connected%s", host, port,
		/* cli->ssl ? " via SSL" : */ "");

	strcpy(cli->addr_host, host);
	strcpy(cli->addr_port, port);

	if (event_add(&cli->ev, NULL) < 0) {
		applog(LOG_ERR, "unable to ready srv fd for polling");
		goto err_out_fd;
	}
	cli->ev_mask = EV_READ;

	atcp_read(&cli->rst, &cli->ubbp, sizeof(cli->ubbp),
		  cli_rd_ubbp, cli);

	return;

err_out_fd:
err_out:
	cli_free(cli);
}

static int net_write_port(const char *port_file, const char *port_str)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		HAIL_INFO(&srv_log, "Cannot create port file %s: %s",
			  port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s\n", port_str);
	fclose(portf);
	return 0;
}

static void net_close(void)
{
	struct server_socket *tmp, *iter;

	list_for_each_entry_safe(tmp, iter, &cld_srv.sockets, sockets_node) {
		if (tmp->fd >= 0) {
			if (event_del(&tmp->ev) < 0)
				HAIL_WARN(&srv_log, "Event delete(%d) failed",
					  tmp->fd);
			if (close(tmp->fd) < 0)
				HAIL_WARN(&srv_log, "Close(%d) failed: %s",
					  tmp->fd, strerror(errno));
			tmp->fd = -1;
		}

		list_del(&tmp->sockets_node);
		free(tmp);
	}
}

static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_socket *sock;
	int fd, rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		syslogerr("tcp socket");
		return -errno;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		syslogerr("tcp bind");
		close(fd);
		return -errno;
	}

	if (listen(fd, 100) < 0) {
		syslogerr("tcp listen");
		close(fd);
		return -errno;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc) {
		close(fd);
		return -errno;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		close(fd);
		return -ENOMEM;
	}

	sock->fd = fd;
	INIT_LIST_HEAD(&sock->sockets_node);

	event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
		  tcp_srv_event, sock);

	if (event_add(&sock->ev, NULL) < 0) {
		free(sock);
		close(fd);
		return -EIO;
	}

	list_add_tail(&sock->sockets_node, &cld_srv.sockets);

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
	fd6 = net_open_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, sizeof(addr6), &addr6);

	if (fd6 >= 0) {
		addr_len = sizeof(addr6);
		if (getsockname(fd6, (struct sockaddr *) &addr6,
				&addr_len) != 0) {
			rc = errno;
			HAIL_ERR(&srv_log, "getsockname failed: %s", strerror(rc));
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
	fd4 = net_open_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, sizeof(addr4), &addr4);

	if (!port) {
		if (fd4 < 0)
			return fd4;

		addr_len = sizeof(addr4);
		if (getsockname(fd4, (struct sockaddr *) &addr4,
				&addr_len) != 0) {
			rc = errno;
			HAIL_ERR(&srv_log, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr4.sin_port);
	}

	HAIL_INFO(&srv_log, "Listening on port %u", port);

	if (cld_srv.port_file) {
		char portstr[7];
		snprintf(portstr, sizeof(portstr), "%u", port);
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
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, portstr, &hints, &res0);
	if (rc) {
		HAIL_ERR(&srv_log, "getaddrinfo(*:%s) failed: %s",
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

		HAIL_INFO(&srv_log, "Listening on %s port %s",
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
	HAIL_ERR(&srv_log, "SIGSEGV");
	exit(1);
}

static void term_signal(int signo)
{
	server_running = false;
	event_loopbreak();
}

static void stats_signal(int signo)
{
	dump_stats = true;
	event_loopbreak();
}

#define X(stat) \
	HAIL_INFO(&srv_log, "STAT %s %lu", #stat, cld_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(garbage);
}

#undef X

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	int v;

	switch(key) {
	case 'd':
		cld_srv.data_dir = arg;
		break;
	case 'D':
		v = atoi(arg);
		if (v < 0 || v > 2) {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		if (v >= 1)
			srv_log.debug = true;
		if (v >= 2)
			srv_log.verbose = true;
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
	while (server_running) {
		cld_srv.stats.poll++;
		event_dispatch();

		gettimeofday(&current_time, NULL);

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
	}

	return 0;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

	INIT_LIST_HEAD(&cld_srv.sockets);

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

	cld_srv.evbase_main = event_init();

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

	evtimer_set(&cld_srv.chkpt_timer, cldb_checkpoint, NULL);
	add_chkpt_timer();

	rc = 1;

	cld_srv.sessions = g_hash_table_new(sess_hash, sess_equal);
	if (!cld_srv.sessions)
		goto err_out_pid;

	if (sess_load(cld_srv.sessions) != 0)
		goto err_out_pid;

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_pid;

	HAIL_INFO(&srv_log, "initialized: %s%s%s",
		  srv_log.debug ? "debug" : "nodebug",
		  srv_log.verbose ? ", verbose" : "",
		  strict_free ? ", strict-free" : "");

	/*
	 * execute main loop
	 */
	rc = main_loop();

	HAIL_INFO(&srv_log, "shutting down");

	if (strict_free)
		if (evtimer_del(&cld_srv.chkpt_timer) < 0)
			HAIL_WARN(&srv_log, "chkpt timer del failed");

	if (cld_srv.cldb.up)
		cldb_down(&cld_srv.cldb);
	cldb_fini(&cld_srv.cldb);

err_out_pid:
	unlink(cld_srv.pid_file);
	close(cld_srv.pid_fd);
err_out:
	if (strict_free) {
		net_close();
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
			HAIL_CRIT(&srv_log, "Cannot allocate new root inode");
			goto err_;
		}

		inode->time_create =
		inode->time_modify = cpu_to_le64(current_time.tv_sec);
		inode->version = cpu_to_le32(1);

		rc = cldb_inode_put(txn, inode, 0);
		if (rc) {
			free(inode);
			HAIL_CRIT(&srv_log, "Cannot allocate new root inode");
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


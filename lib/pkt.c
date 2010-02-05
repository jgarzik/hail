
/*
 * Copyright 2010, Colin McCabe
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
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <syslog.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cld-private.h>
#include <cld_common.h>
#include "cld_msg_rpc.h"
#include <hail_log.h>

int __cld_authcheck(struct hail_log *log, const char *key,
		    const void *buf, size_t buf_len, const void *sha)
{
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned int md_len = 0;

	if (!key || !*key)
		return -EINVAL;

	HMAC(EVP_sha1(), key, strlen(key), buf, buf_len, md, &md_len);

	if (md_len != SHA_DIGEST_LENGTH) {
		HAIL_ERR(log, "%s BUG: md_len != SHA_DIGEST_LENGTH", __func__);
		return -EBADMSG; /* BUG */
	}

	if (memcmp(md, sha, SHA_DIGEST_LENGTH))
		return -EPERM;

	return 0;
}

int __cld_authsign(struct hail_log *log, const char *key,
		   const void *buf, size_t buf_len, void *sha)
{
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned int md_len = 0;

	if (!key || !*key) {
		HAIL_DEBUG(log, "%s: invalid key\n", __func__);
		return -EINVAL;
	}

	HMAC(EVP_sha1(), key, strlen(key), buf, buf_len, md, &md_len);

	if (md_len != SHA_DIGEST_LENGTH) {
		HAIL_ERR(log, "%s BUG: md_len != SHA_DIGEST_LENGTH", __func__);
		return -EBADMSG;
	}

	memcpy(sha, md, SHA_DIGEST_LENGTH);

	return 0;
}

const char *__cld_opstr(enum cld_msg_op op)
{
	switch (op) {
	case CMO_NOP:		return "CMO_NOP";
	case CMO_NEW_SESS:	return "CMO_NEW_SESS";
	case CMO_OPEN:		return "CMO_OPEN";
	case CMO_GET_META:	return "CMO_GET_META";
	case CMO_GET:		return "CMO_GET";
	case CMO_PUT:		return "CMO_PUT";
	case CMO_CLOSE:		return "CMO_CLOSE";
	case CMO_DEL:		return "CMO_DEL";
	case CMO_LOCK:		return "CMO_LOCK";
	case CMO_UNLOCK:	return "CMO_UNLOCK";
	case CMO_TRYLOCK:	return "CMO_TRYLOCK";
	case CMO_ACK:		return "CMO_ACK";
	case CMO_END_SESS:	return "CMO_END_SESS";
	case CMO_PING:		return "CMO_PING";
	case CMO_NOT_MASTER:	return "CMO_NOT_MASTER";
	case CMO_EVENT:		return "CMO_EVENT";
	case CMO_ACK_FRAG:	return "CMO_ACK_FRAG";
	default:		return "(unknown)";
	}
}

const char *__cld_pkt_hdr_to_str(char *scratch,
				 const char *pkt_hdr, size_t pkt_len)
{
	XDR xin;
	struct cld_pkt_hdr pkt;
	bool bad_magic;
	char temp[50], temp2[50];
	uint64_t seqid;
	struct cld_pkt_ftr *foot;
	size_t hdr_len;

	temp[0] = '\0';
	temp2[0] = '\0';
	foot = (struct cld_pkt_ftr *)(pkt_hdr + pkt_len - CLD_PKT_FTR_LEN);
	seqid = le64_to_cpu(foot->seqid);

	if (pkt_len <= CLD_PKT_FTR_LEN) {
		snprintf(scratch, PKT_HDR_TO_STR_SCRATCH_LEN,
			 "[MALFORMED: only %zu bytes]", pkt_len);
		return scratch;
	}
	xdrmem_create(&xin, (void *)pkt_hdr, pkt_len - CLD_PKT_FTR_LEN,
		      XDR_DECODE);
	memset(&pkt, 0, sizeof(pkt));
	if (!xdr_cld_pkt_hdr(&xin, &pkt)) {
		xdr_destroy(&xin);
		snprintf(scratch, PKT_HDR_TO_STR_SCRATCH_LEN,
			 "[MALFORMED: can't parse]");
		return scratch;
	}
	hdr_len = xdr_getpos(&xin);
	xdr_destroy(&xin);

	bad_magic = !!(memcmp(&pkt.magic, CLD_PKT_MAGIC, sizeof(pkt.magic)));
	if (pkt.mi.order & CLD_PKT_IS_FIRST) {
		struct cld_pkt_msg_infos *infos =
			&pkt.mi.cld_pkt_msg_info_u.mi;
		snprintf(temp, sizeof(temp), "[TYPE:%s, XID:%llx]",
			 __cld_opstr(infos->op),
			 (unsigned long long) infos->xid);
		switch (infos->op) {
		case CMO_ACK_FRAG: {
			XDR x;
			struct cld_msg_ack_frag ack;
			memset(&ack, 0, sizeof(ack));
			xdrmem_create(&x, ((char *)pkt_hdr) + hdr_len,
				      pkt_len - hdr_len - CLD_PKT_FTR_LEN,
				      XDR_DECODE);
			if (!xdr_cld_msg_ack_frag(&x, &ack)) {
				xdr_destroy(&x);
				snprintf(temp2, sizeof(temp2), "{MALFORMED}");
				break;
			}
			snprintf(temp2, sizeof(temp2), "{seqid:%llx}",
				 (unsigned long long) ack.seqid);
			xdr_destroy(&x);
			break;
		}
		default:
			break;
		}
	} else {
		snprintf(temp, sizeof(temp), "[CONT]");
	}

	snprintf(scratch, PKT_HDR_TO_STR_SCRATCH_LEN,
		"<%s%s%s> "
		"%s USER:'%s' SEQID:%llx %s",
		((pkt.mi.order & CLD_PKT_IS_FIRST) ? "1st" : ""),
		((pkt.mi.order & CLD_PKT_IS_LAST) ? "End" : ""),
		(bad_magic ? "B" : ""),
		temp, pkt.user,
		(unsigned long long) seqid,
		temp2);
	xdr_free((xdrproc_t)xdr_cld_pkt_hdr, (char *)&pkt);
	return scratch;
}

void __cld_dump_buf(const void *buf, size_t len)
{
	const unsigned char *buff = buf;
	size_t off = 0;
	do {
		int i;
		for (i = 0; i < 8; i++) {
			if (!len)
				break;
			printf("%02x ", buff[off++]);
			len--;
		}
		printf("\n");
	} while (len);
}

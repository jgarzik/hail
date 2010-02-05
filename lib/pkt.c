
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
#include <errno.h>
#include <syslog.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cldc.h>

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


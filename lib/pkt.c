
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

const char *__cld_opstr(enum cld_msg_ops op)
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


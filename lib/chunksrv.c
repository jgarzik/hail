
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
#include "chunkd-config.h"

#include <string.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <chunk_msg.h>

size_t req_len(const struct chunksrv_req *req)
{
	size_t len;

	len = sizeof(struct chunksrv_req) + GUINT16_FROM_LE(req->key_len);

	return len;
}

void chreq_sign(struct chunksrv_req *req, const char *key, char *b64hmac_out)
{
	unsigned int len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	int save = 0, state = 0, b64_len;
	const void *p = req;

	HMAC(EVP_sha1(), key, strlen(key), p, req_len(req), md, &len);

	b64_len = g_base64_encode_step(md, len, FALSE, b64hmac_out,
				       &state, &save);
	b64_len += g_base64_encode_close(FALSE, b64hmac_out + b64_len,
					 &state, &save);
	b64hmac_out[b64_len] = 0;
}

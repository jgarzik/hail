#ifndef __CHUNK_MSG_H__
#define __CHUNK_MSG_H__

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

#include <stdint.h>

#define CHUNKD_MAGIC "CHUNKDv1"

enum {
	CHD_MAGIC_SZ		= 8,
	CHD_USER_SZ		= 64,
	CHD_KEY_SZ		= 1024,	/* key size limit; max 65534 (fffe) */
	CHD_CSUM_SZ		= 64,
	CHD_SIG_SZ		= 64,
};

enum chunksrv_ops {
	CHO_NOP			= 0,
	CHO_GET			= 1,
	CHO_GET_META		= 2,
	CHO_PUT			= 3,
	CHO_DEL			= 4,
	CHO_LIST		= 5,
	CHO_LOGIN		= 6,
	CHO_TABLE_OPEN		= 7,
};

enum chunk_errcode {
	che_Success			= 0,
	che_AccessDenied		= 1,
	che_InternalError		= 2,
	che_InvalidArgument		= 3,
	che_InvalidURI			= 4,
	che_NoSuchKey			= 5,
	che_SignatureDoesNotMatch	= 6,
	che_InvalidKey			= 7,
	che_InvalidTable		= 8,
};

enum chunk_flags {
	CHF_SYNC		= (1 << 0),	/* force write to media */
	CHF_TBL_CREAT		= (1 << 1),	/* create tbl, if needed */
	CHF_TBL_EXCL		= (1 << 2),	/* fail, if tbl exists */
};

struct chunksrv_req {
	uint8_t			magic[CHD_MAGIC_SZ];	/* CHUNKD_MAGIC */
	uint8_t			op;			/* CHO_xxx */
	uint8_t			flags;			/* CHF_xxx */
	uint16_t		key_len;
	uint32_t		nonce;	/* random number, to stir checksum */
	uint64_t		data_len;		/* len of addn'l data */
	char			sig[CHD_SIG_SZ];	/* HMAC signature */

	/* variable-length key */
};

struct chunksrv_resp {
	uint8_t			magic[CHD_MAGIC_SZ];	/* CHUNKD_MAGIC */
	uint8_t			resp_code;		/* chunk_errcode's */
	uint8_t			rsv1[3];
	uint32_t		nonce;	/* txn id, copied from request */
	uint64_t		data_len;		/* len of addn'l data */
	char			checksum[CHD_CSUM_SZ];	/* SHA1 checksum */
};

struct chunksrv_resp_get {
	struct chunksrv_resp	resp;
	uint64_t		mtime;
};

#endif /* __CHUNK_MSG_H__ */

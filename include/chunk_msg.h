#ifndef __CHUNK_MSG_H__
#define __CHUNK_MSG_H__

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
};

enum errcode {
	Success,
	AccessDenied,
	InternalError,
	InvalidArgument,
	InvalidURI,
	MissingContentLength,
	NoSuchKey,
	PreconditionFailed,
	SignatureDoesNotMatch,
	InvalidKey,
};

struct chunksrv_req {
	uint8_t			magic[CHD_MAGIC_SZ];	/* CHUNKD_MAGIC */
	uint8_t			op;			/* CHO_xxx */
	uint8_t			rsv1[1];
	uint16_t		key_len;
	uint32_t		nonce;	/* random number, to stir checksum */
	uint64_t		data_len;		/* len of addn'l data */
	char			user[CHD_USER_SZ];	/* username */
	char			sig[CHD_SIG_SZ];	/* HMAC signature */

	/* variable-length key */
};

struct chunksrv_resp {
	uint8_t			magic[CHD_MAGIC_SZ];	/* CHUNKD_MAGIC */
	uint8_t			resp_code;		/* errcode's */
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

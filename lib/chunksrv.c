
#include "chunkd-config.h"
#include <string.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <chunk_msg.h>

size_t req_len(const struct chunksrv_req *req)
{
	return sizeof(*req);
}

void chreq_sign(struct chunksrv_req *req, const char *key, char *b64hmac_out)
{
	unsigned int len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	int save = 0, state = 0, b64_len;
	const void *p = req;

	HMAC(EVP_sha1(), key, strlen(key), p, sizeof(*req), md, &len);

	b64_len = g_base64_encode_step(md, len, FALSE, b64hmac_out,
				       &state, &save);
	b64_len += g_base64_encode_close(FALSE, b64hmac_out + b64_len,
					 &state, &save);
	b64hmac_out[b64_len] = 0;
}

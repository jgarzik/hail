#ifndef __CHUNKSRV_H__
#define __CHUNKSRV_H__

#include <chunk_msg.h>

extern void chreq_sign(struct chunksrv_req *req, const char *key,
		       char *b64hmac_out);

#endif /* __CHUNKSRV_H__ */

#ifndef __CHUNKSRV_H__
#define __CHUNKSRV_H__

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

#include <chunk_msg.h>

extern size_t req_len(const struct chunksrv_req *req);
extern void chreq_sign(struct chunksrv_req *req, const char *key,
		       char *b64hmac_out);

#endif /* __CHUNKSRV_H__ */

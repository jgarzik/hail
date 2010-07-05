#ifndef __CLD_COMMON_H__
#define __CLD_COMMON_H__

/*
 * Copyright 2009 Red Hat, Inc.
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
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include <openssl/sha.h>
#include <cld_msg_rpc.h>

#define CLD_ALIGN8(n) ((8 - ((n) & 7)) & 7)

struct hail_log;

struct cld_timer {
	bool			fired;
	bool			on_list;
	void			(*cb)(struct cld_timer *);
	void			*userdata;
	time_t			expires;
	char			name[32];
};

struct cld_timer_list {
	GList *list;		/* of struct cld_timer */
	time_t			runmark;
};

extern void cld_timer_add(struct cld_timer_list *tlist, struct cld_timer *timer,
			  time_t expires);
extern void cld_timer_del(struct cld_timer_list *tlist, struct cld_timer *timer);
extern time_t cld_timers_run(struct cld_timer_list *tlist);

static inline void cld_timer_init(struct cld_timer *timer, const char *name,
	void (*cb)(struct cld_timer *), void *userdata)
{
	memset(timer, 0, sizeof(*timer));
	timer->cb = cb;
	timer->userdata = userdata;
	strncpy(timer->name, name, sizeof(timer->name));
	timer->name[sizeof(timer->name) - 1] = 0;
}

extern unsigned long long cld_sid2llu(const uint8_t *sid);
extern void cld_rand64(void *p);
extern const char *cld_errstr(enum cle_err_codes ecode);
extern int cld_readport(const char *fname);

/*** Validate the HMAC signature of a byte buffer.
 *
 * @param log		log to write to
 * @param key		The key, as a NULL-terminated string
 * @param buf		The buffer
 * @param buf_len	Length of the buffer
 * @param sha		The signature itself. Must be of length exactly
 *			SHA_DIGEST_LENGTH
 *
 * @return		0 on success; error code otherwise
 */
extern int cld_authcheck(struct hail_log *log, const char *key,
			   const void *buf, size_t buf_len, const void *sha);

/*** Sign a byte buffer.
 *
 * @param log		log to write to
 * @param key		The key, as a NULL-terminated string
 * @param buf		The buffer
 * @param buf_len	Length of the buffer
 * @param sha		(out param) The signature itself. Must be of length
 *			exactly SHA_DIGEST_LENGTH
 *
 * @return		0 on success; error code otherwise
 */
extern int cld_authsign(struct hail_log *log, const char *key,
			  const void *buf, size_t buf_len, void *sha);

/* Returns a constant string representing a message operation */
extern const char *cld_opstr(enum cld_msg_op);

/*
 * We use a unified format for sid so it can be searched in log files (* in vi).
 */
#define SIDFMT		"%016llX"
#define SIDARG(sid)	cld_sid2llu(sid)

/* Returns a string representation of a packet header
 *
 * @param scratch		(out param) buffer of length
 *				PKT_HDR_TO_STR_SCRATCH_LEN
 * @param pkt_hdr		packet header
 * @param pkt_len		length of packet
 *
 * @return			pointer to 'scratch'
 */
extern const char *cld_pkt_hdr_to_str(char *scratch,
					const char *pkt_hdr, size_t pkt_len);

extern void __cld_dump_buf(const void *buf, size_t len);

/** Footer that appears at the end of each packet */
struct __attribute__((packed)) cld_pkt_ftr {
	uint64_t seqid;				/**< packet sequence ID */
	char sha[SHA_DIGEST_LENGTH];		/**< packet signature */
};

/** Length of the packet footer. This size is fixed */
#define CLD_PKT_FTR_LEN sizeof(struct cld_pkt_ftr)

#define PKT_HDR_TO_STR_SCRATCH_LEN 128

#endif /* __CLD_COMMON_H__ */

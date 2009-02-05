#ifndef __CLD_MSG_H__
#define __CLD_MSG_H__

#include <stdint.h>

#define CLD_MAGIC	"CLDv1cli"

enum {
	CLD_MAGIC_SZ		= 8,
};

enum cld_msg_ops {
	cmo_nop			= 0,		/* no op */
	cmo_new_cli		= 1,		/* new client */
};

struct cld_msg {
	uint8_t		magic[CLD_MAGIC_SZ];	/* magic number; constant */
	uint8_t		msgid[8];		/* message id */
	uint8_t		clid[8];		/* client id */
	uint8_t		op;			/* operation code */
	uint8_t		n_data;			/* num data pkts; max 64 */
	uint8_t		res1[2];
	uint32_t	data_len;		/* total size of all data pkts*/
};

#endif /* __CLD_MSG_H__ */

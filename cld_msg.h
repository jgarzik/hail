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

enum cle_err_codes {
	CLE_OK			= 0,		/* success / no error */
	CLE_CLI_EXISTS		= 1,		/* client exists */
	CLE_DB_ERR		= 2,		/* db error */
};

struct cld_msg_hdr {
	uint8_t		magic[CLD_MAGIC_SZ];	/* magic number; constant */
	uint8_t		msgid[8];		/* message id */
	uint8_t		clid[8];		/* client id */
	uint8_t		op;			/* operation code */
	uint8_t		n_data;			/* num data pkts; max 64 */
	uint8_t		res1[2];
	uint32_t	data_len;		/* total size of all data pkts*/
};

struct cld_msg_resp {
	struct cld_msg_hdr	hdr;

	uint32_t		code;
};

#endif /* __CLD_MSG_H__ */

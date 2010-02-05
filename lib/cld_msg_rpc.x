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

const CLD_PKT_MAGIC = "CLDc1pkt";
const CLD_SID_SZ = 8;

const CLD_INODE_NAME_MAX = 256; /**< max total pathname len */

const CLD_MAX_USERNAME = 32;

const CLD_MAX_PKT_MSG_SZ = 1024; /**< The maximum number of message bytes we'll
				   put in a single packet */

const CLD_MAX_PAYLOAD_SZ = 131072; /**< Maximum length of the data that can be
					sent with get or put. In some sense,
					this is part of cld's API, and
					shouldn't be changed lightly.  */

const CLD_MAX_MSG_SZ = 196608; /**< Maximum size of a single message
					including all packets. */

const CLD_MAX_SECRET_KEY = 128; /**< includes req. nul */

/** available RPC operations */
enum cld_msg_op {
	/* client -> server */
	CMO_NOP			= 0,	/**< no op */
	CMO_NEW_SESS		= 1,	/**< new session */
	CMO_OPEN		= 2,	/**< open file */
	CMO_GET_META		= 3,	/**< get metadata */
	CMO_GET			= 4,	/**< get metadata + data */
	CMO_PUT			= 6,	/**< put data */
	CMO_CLOSE		= 7,	/**< close file */
	CMO_DEL			= 8,	/**< delete file */
	CMO_LOCK		= 9,	/**< lock */
	CMO_UNLOCK		= 10,	/**< unlock */
	CMO_TRYLOCK		= 11,	/**< trylock */
	CMO_ACK			= 12,	/**< ack of seqid rx'd */
	CMO_END_SESS		= 13,	/**< end session */

	/* server -> client */
	CMO_PING		= 14,	/**< server to client ping */
	CMO_NOT_MASTER		= 15,	/**< I am not the master! */
	CMO_EVENT		= 16,	/**< server->cli async event */
	CMO_ACK_FRAG		= 17, 	/**< ack partial msg */

	CMO_AFTER_LAST
};

/** CLD error codes */
enum cle_err_codes {
	CLE_OK			= 0,	/**< success / no error */
	CLE_SESS_EXISTS		= 1,	/**< session exists */
	CLE_SESS_INVAL		= 2,	/**< session doesn't exist */
	CLE_DB_ERR		= 3,	/**< db error */
	CLE_BAD_PKT		= 4,	/**< invalid/corrupted packet */
	CLE_INODE_INVAL		= 5,	/**< inode doesn't exist */
	CLE_NAME_INVAL		= 6,	/**< inode name invalid */
	CLE_OOM			= 7,	/**< server out of memory */
	CLE_FH_INVAL		= 8,	/**< file handle invalid */
	CLE_DATA_INVAL		= 9,	/**< invalid data pkt */
	CLE_LOCK_INVAL		= 10,	/**< invalid lock */
	CLE_LOCK_CONFLICT 	= 11,	/**< conflicting lock held */
	CLE_LOCK_PENDING	= 12,	/**< lock waiting to be acq. */
	CLE_MODE_INVAL		= 13,	/**< op incompat. w/ file mode */
	CLE_INODE_EXISTS	= 14,	/**< inode exists */
	CLE_DIR_NOTEMPTY	= 15,	/**< dir not empty */
	CLE_INTERNAL_ERR	= 16,	/**< nonspecific internal err */
	CLE_TIMEOUT 		= 17,	/**< session timed out */
	CLE_SIG_INVAL 		= 18	/**< HMAC sig bad / auth failed */
};

/** availble OPEN mode flags */
enum cld_open_modes {
	COM_READ		= 0x01,	/**< read */
	COM_WRITE		= 0x02,	/**< write */
	COM_LOCK		= 0x04,	/**< lock */
	COM_ACL			= 0x08,	/**< ACL update */
	COM_CREATE		= 0x10,	/**< create file, if not exist */
	COM_EXCL		= 0x20,	/**< fail create if file exists */
	COM_DIRECTORY		= 0x40	/**< operate on a directory */
};

/** potential events client may receive */
enum cld_events {
	CE_UPDATED		= 0x01,	/**< contents updated */
	CE_DELETED		= 0x02,	/**< inode deleted */
	CE_LOCKED		= 0x04,	/**< lock acquired */
	CE_MASTER_FAILOVER	= 0x08,	/**< master failover */
	CE_SESS_FAILED		= 0x10
};

/** LOCK flags */
enum cld_lock_flags {
	CLF_SHARED		= 0x01	/**< a shared (read) lock */
};

/** Describes whether a packet begins, continues, or ends a message. */
enum cld_pkt_order_t {
	CLD_PKT_ORD_MID = 0x0,
	CLD_PKT_ORD_FIRST = 0x1,
	CLD_PKT_ORD_LAST = 0x2,
	CLD_PKT_ORD_FIRST_LAST = 0x3
};
const CLD_PKT_IS_FIRST = 0x1;
const CLD_PKT_IS_LAST = 0x2;

/** Information that appears only in the first packet */
struct cld_pkt_msg_infos {
	hyper			xid;		/**< opaque message id */
	enum cld_msg_op		op;		/**< message operation */
};

/** Information about the message contained in this packet */
union cld_pkt_msg_info switch (enum cld_pkt_order_t order) {
	case CLD_PKT_ORD_MID:
	case CLD_PKT_ORD_LAST:
		void;
	case CLD_PKT_ORD_FIRST:
	case CLD_PKT_ORD_FIRST_LAST:
		struct cld_pkt_msg_infos mi;
};

/** header for each packet */
struct cld_pkt_hdr {
	hyper		magic;		/**< magic number; constant */
	hyper		sid;		/**< client id */
	string		user<CLD_MAX_USERNAME>;	/**< authenticated user */
	struct cld_pkt_msg_info mi;
};

/** generic response for PUT, CLOSE, DEL, LOCK, UNLOCK */
struct cld_msg_generic_resp {
	enum cle_err_codes	code;		/**< error code, CLE_xxx */
	hyper			xid_in;		/**< C->S xid */
};

/** ACK-FRAG message */
struct cld_msg_ack_frag {
	hyper			seqid;		/**< sequence id to ack */
};

/** OPEN message */
struct cld_msg_open {
	int			mode;		/**< open mode, COM_xxx */
	int			events;		/**< events mask, CE_xxx */
	string			inode_name<CLD_INODE_NAME_MAX>;
};

/** OPEN message response */
struct cld_msg_open_resp {
	struct cld_msg_generic_resp msg;
	hyper			fh;		/**< handle opened */
};

/** GET message */
struct cld_msg_get {
	hyper			fh;		/**< open file handle */
};

/** GET message response */
struct cld_msg_get_resp {
	struct cld_msg_generic_resp msg;
	hyper			inum;		/**< unique inode number */
	hyper			vers;		/**< inode version */
	hyper			time_create;	/**< creation time */
	hyper			time_modify;	/**< last modification time */
	int			flags;		/**< inode flags; CIFL_xxx */
	string			inode_name<CLD_INODE_NAME_MAX>;
	opaque			data<CLD_MAX_PAYLOAD_SZ>;
};

/** PUT message */
struct cld_msg_put {
	hyper			fh;		/**< open file handle */
	opaque			data<CLD_MAX_PAYLOAD_SZ>;
};

/** CLOSE message */
struct cld_msg_close {
	hyper			fh;		/**< open file handle */
};

/** DEL message */
struct cld_msg_del {
	string			inode_name<CLD_INODE_NAME_MAX>;
};

/** UNLOCK message */
struct cld_msg_unlock {
	uint64_t		fh;		/**< open file handle */
};

/** LOCK message */
struct cld_msg_lock {
	hyper			fh;		/**< open file handle */
	int			flags;		/**< CLF_xxx */
};

/** Server-to-client EVENT message */
struct cld_msg_event {
	hyper			fh;		/**< open file handle */
	int			events;		/**< CE_xxx */
};

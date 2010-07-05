#ifndef __HAIL_PRIVATE_H__
#define __HAIL_PRIVATE_H__

#include "hail-config.h"

#include <rpc/xdr.h>

#ifndef HAVE_XDR_SIZEOF
extern u_long xdr_sizeof (xdrproc_t, void *);
#endif

#endif /* __HAIL_PRIVATE_H__ */

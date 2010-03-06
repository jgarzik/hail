
INCLUDES	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@			\
		  -DCLD_LIBDIR=\""$(libdir)"\"	\
		  -DCLD_LOCAL_STATE_DIR="\"$(localstatedir)\""

sbin_PROGRAMS	= cld cldbadm

cld_SOURCES	= cldb.h cld.h \
		  ../lib/common.c ../lib/libtimer.c ../lib/pkt.c \
		  cldb.c msg.c server.c session.c util.c \
		  ../lib/cld_msg_rpc_xdr.c
cld_LDADD	= @CRYPTO_LIBS@ @GLIB_LIBS@ @DB4_LIBS@

cldbadm_SOURCES	= cldb.h cldbadm.c
cldbadm_LDADD	= @CRYPTO_LIBS@ @GLIB_LIBS@ @DB4_LIBS@


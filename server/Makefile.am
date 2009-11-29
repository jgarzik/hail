
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@ \
		  -DCLD_LIBDIR=\""$(libdir)"\" \
		  -DCLD_LOCAL_STATE_DIR="\"$(localstatedir)\""

sbin_PROGRAMS	= cld cldbadm

cld_SOURCES	= cldb.h cld.h \
		  ../lib/common.c \
		  cldb.c msg.c server.c session.c util.c
cld_LDADD	= ../lib/libtimer.a \
		  @CRYPTO_LIBS@ @GLIB_LIBS@ @DB4_LIBS@ @ARGP_LIBS@

cldbadm_SOURCES	= cldb.h cldbadm.c
cldbadm_LDADD	= @CRYPTO_LIBS@ @GLIB_LIBS@ @DB4_LIBS@ @ARGP_LIBS@


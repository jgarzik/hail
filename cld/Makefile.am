
AM_CPPFLAGS	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@			\
		  -DCLD_LIBDIR=\""$(libdir)"\"	\
		  -DCLD_LOCAL_STATE_DIR="\"$(localstatedir)\""

sbin_PROGRAMS	= cld
noinst_PROGRAMS	= cldbadm

cld_SOURCES	= cldb.h cld.h \
		  cldb.c msg.c server.c session.c util.c
cld_LDADD	= \
		  ../lib/libhail.la @GLIB_LIBS@ @CRYPTO_LIBS@ \
		  @SSL_LIBS@ @BDB_LIBS@ @XML_LIBS@ @LIBCURL@ \
		  @EVENT_LIBS@

cldbadm_SOURCES	= cldb.h cldbadm.c
cldbadm_LDADD	= @CRYPTO_LIBS@ @GLIB_LIBS@ @BDB_LIBS@


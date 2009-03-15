
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= chunkd

chunkd_SOURCES	= chunkd.h		\
		  be-fs.c object.c server.c util.c
chunkd_LDADD	= ../lib/libhttputil.a	\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ \
		  @SSL_LIBS@ @EVENT_LIBS@ @ARGP_LIBS@


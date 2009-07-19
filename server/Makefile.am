
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= chunkd

chunkd_SOURCES	= chunkd.h		\
		  ../lib/chunksrv.c	\
		  be-fs.c object.c server.c config.c cldu.c util.c
chunkd_LDADD	= \
		  @CLDC_LIBS@ @GLIB_LIBS@ @CRYPTO_LIBS@ \
		  @SSL_LIBS@ @EVENT_LIBS@ @ARGP_LIBS@ @SOCKET_LIBS@

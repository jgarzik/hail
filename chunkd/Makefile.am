
AM_CPPFLAGS	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@ @TOKYOCABINET_CFLAGS@

sbin_PROGRAMS	= chunkd

chunkd_SOURCES	= chunkd.h		\
		  be-fs.c object.c server.c selfcheck.c config.c cldu.c util.c \
		  objcache.c
chunkd_LDADD	= \
		  ../lib/libhail.la @GLIB_LIBS@ @CRYPTO_LIBS@ \
		  @EVENT_LIBS@ \
		  @SSL_LIBS@ @TOKYOCABINET_LIBS@ @XML_LIBS@ @LIBCURL@

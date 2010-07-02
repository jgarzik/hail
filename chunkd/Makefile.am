
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@ @CLDC_CFLAGS@ \
		  @TOKYOCABINET_CFLAGS@

sbin_PROGRAMS	= chunkd

chunkd_SOURCES	= chunkd.h		\
		  ../lib/chunksrv.c	\
		  be-fs.c object.c server.c selfcheck.c config.c cldu.c util.c \
		  objcache.c
chunkd_LDADD	= \
		  @CLDC_LIBS@ @GLIB_LIBS@ @CRYPTO_LIBS@ \
		  @SSL_LIBS@ @TOKYOCABINET_LIBS@

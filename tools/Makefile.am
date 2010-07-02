
INCLUDES	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@

bin_PROGRAMS	= cldcli chcli
noinst_PROGRAMS	= cldfuse

cldcli_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@

cldfuse_CFLAGS	= @FUSE_CFLAGS@
cldfuse_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@
cldfuse_LDFLAGS	= @FUSE_LIBS@

chcli_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@


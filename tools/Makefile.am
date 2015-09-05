
AM_CPPFLAGS	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@

bin_PROGRAMS	= cldcli chcli
noinst_PROGRAMS	= $(HAIL_FUSE_PROGS)
EXTRA_PROGRAMS	= cldfuse

cldcli_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@ @LIBCURL@

cldfuse_CFLAGS	= @FUSE_CFLAGS@
cldfuse_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@ @LIBCURL@
cldfuse_LDFLAGS	= @FUSE_LIBS@

chcli_LDADD	= ../lib/libhail.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @SSL_LIBS@ @XML_LIBS@ @LIBCURL@


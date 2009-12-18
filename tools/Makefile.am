
INCLUDES	= -I$(top_srcdir)/include	\
		  @GLIB_CFLAGS@ @XML_CPPFLAGS@

bin_PROGRAMS	= chcli

chcli_LDADD	= ../lib/libchunkdc.la		\
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @XML_LIBS@ @SSL_LIBS@ \
		  @ARGP_LIBS@


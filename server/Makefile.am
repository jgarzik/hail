
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= storaged

storaged_SOURCES	= storaged.h		\
		  object.c server.c util.c volume.c
storaged_LDADD	= ../lib/libhttputil.a	\
		  @PCRE_LIBS@ @GLIB_LIBS@ @SSL_LIBS@ @SQLITE_LIBS@


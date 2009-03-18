
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= cld

cld_SOURCES	= cldb.h cld.h \
		  cldb.c msg.c server.c session.c util.c
cld_LDADD	= @GLIB_LIBS@ @DB4_LIBS@ @EVENT_LIBS@ @ARGP_LIBS@


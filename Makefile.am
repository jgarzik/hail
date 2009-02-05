##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

sbin_PROGRAMS	= cld

cld_SOURCES	= cldb.h cld.h cldb.c server.c util.c
cld_LDADD	= @GLIB_LIBS@ @DB4_LIBS@

EXTRA_DIST	= autogen.sh


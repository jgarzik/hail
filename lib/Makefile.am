
INCLUDES		= -I$(top_srcdir)/include	\
			  @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =
	libchunkdc.pc.in libchunkdc-uninstalled.pc.in

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libchunkdc.la

libchunkdc_la_SOURCES	= chunkdc.c chunksrv.c

libchunkdc_la_LDFLAGS = \
	-version-info $(LIBCHUNKDC_CURRENT):$(LIBCHUNKDC_REVISION):$(LIBCHUNKDC_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libchunkdc.pc


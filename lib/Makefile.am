
INCLUDES		= -I$(top_srcdir)/include	\
			  @GLIB_CFLAGS@ @XML_CPPFLAGS@

noinst_LIBRARIES	= libchunksrv.a

libchunksrv_a_SOURCES	= chunksrv.c

EXTRA_DIST =
	libchunkdc.pc.in libchunkdc-uninstalled.pc.in

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libchunkdc.la

libchunkdc_la_SOURCES	= chunkdc.c

libchunkdc_la_LDFLAGS = \
	-version-info $(LIBCHUNKDC_CURRENT):$(LIBCHUNKDC_REVISION):$(LIBCHUNKDC_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libchunkdc.pc


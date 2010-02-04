
EXTRA_DIST =
	libcldc.pc.in libcldc-uninstalled.pc.in

INCLUDES		= -I$(top_srcdir)/include	\
			  @GLIB_CFLAGS@

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libcldc.la

libcldc_la_SOURCES	=	\
	cldc.c			\
	cldc-udp.c		\
	cldc-dns.c		\
	common.c		\
	libtimer.c		\
	pkt.c

libcldc_la_LDFLAGS = \
	-version-info $(LIBCLDC_CURRENT):$(LIBCLDC_REVISION):$(LIBCLDC_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcldc.pc


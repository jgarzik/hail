
BUILT_SOURCES		= cld_msg_rpc.h

EXTRA_DIST = \
	libhail.pc.in libhail-uninstalled.pc.in cld_msg_rpc.x

INCLUDES		= -I$(top_srcdir)/include	\
			  @GLIB_CFLAGS@ @XML_CPPFLAGS@

mostlyclean-local:
	rm -f *_rpc.h *_rpc_xdr.c

cld_msg_rpc.h: $(srcdir)/cld_msg_rpc.x
	rpcgen -h $(srcdir)/cld_msg_rpc.x > $@

cld_msg_rpc_xdr.c: $(srcdir)/cld_msg_rpc.x
	rpcgen -c $(srcdir)/cld_msg_rpc.x | grep -v 'register int32_t.*buf' > $@

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libhail.la

libhail_la_SOURCES	=	\
	cldc.c			\
	cldc-udp.c		\
	cldc-dns.c		\
	common.c		\
	libtimer.c		\
	pkt.c			\
	cld_msg_rpc_xdr.c	\
	chunkdc.c		\
	chunksrv.c

libhail_la_LDFLAGS = \
	-version-info $(LIBHAIL_CURRENT):$(LIBHAIL_REVISION):$(LIBHAIL_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhail.pc

include_HEADERS = cld_msg_rpc.h


BUILT_SOURCES		= cld_msg_rpc.h

EXTRA_DIST = \
	libcldc.pc.in libcldc-uninstalled.pc.in cld_msg_rpc.x

INCLUDES		= -I$(top_srcdir)/include	\
			  @GLIB_CFLAGS@

mostlyclean-local:
	rm -f *_rpc.h *_rpc_xdr.c

cld_msg_rpc.h: $(srcdir)/cld_msg_rpc.x
	rpcgen -h $< > $@

cld_msg_rpc_xdr.c: $(srcdir)/cld_msg_rpc.x
	rpcgen -c $< | grep -v 'register int32_t.*buf' > $@

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libcldc.la

libcldc_la_SOURCES	=	\
	cldc.c			\
	cldc-udp.c		\
	cldc-dns.c		\
	common.c		\
	libtimer.c		\
	pkt.c			\
	cld_msg_rpc_xdr.c

libcldc_la_LDFLAGS = \
	-version-info $(LIBCLDC_CURRENT):$(LIBCLDC_REVISION):$(LIBCLDC_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcldc.pc

include_HEADERS = cld_msg_rpc.h

dnl Process this file with autoconf 2.52+ to produce a configure script.
dnl
dnl Copyright (C) 2001 Philipp Rumpf
dnl Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

m4_define([libchunkdc_major_version], [1])
m4_define([libchunkdc_minor_version], [1])
m4_define([libchunkdc_micro_version], [1])
m4_define([libchunkdc_interface_age], [1])
# If you need a modifier for the version number. 
# Normally empty, but can be used to make "fixup" releases.
m4_define([libchunkdc_extraversion], [])

dnl libtool versioning from libchunkdc
m4_define([libchunkdc_current], [m4_eval(100 * libchunkdc_minor_version + libchunkdc_micro_version - libchunkdc_interface_age)])
m4_define([libchunkdc_binary_age], [m4_eval(100 * libchunkdc_minor_version + libchunkdc_micro_version)])
m4_define([libchunkdc_revision], [libchunkdc_interface_age])
m4_define([libchunkdc_age], [m4_eval(libchunkdc_binary_age - libchunkdc_interface_age)])
m4_define([libchunkdc_version], [libchunkdc_major_version().libchunkdc_minor_version().libchunkdc_micro_version()libchunkdc_extraversion()])

AC_INIT([chunkd], [0.2],
        [http://www.kernel.org/pub/software/network/distsrv/])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([server/server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([chunkd-config.h])

LIBCHUNKDC_MAJOR_VERSION=libchunkdc_major_version
LIBCHUNKDC_MINOR_VERSION=libchunkdc_minor_version
LIBCHUNKDC_MICRO_VERSION=libchunkdc_micro_version
LIBCHUNKDC_INTERFACE_AGE=libchunkdc_interface_age

LIBCHUNKDC_CURRENT=libchunkdc_current
LIBCHUNKDC_REVISION=libchunkdc_revision
LIBCHUNKDC_AGE=libchunkdc_age

AC_SUBST(LIBCHUNKDC_CURRENT)
AC_SUBST(LIBCHUNKDC_REVISION)
AC_SUBST(LIBCHUNKDC_AGE)

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AM_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/sendfile.h)

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto)
AC_CHECK_LIB(ssl, SSL_new, SSL_LIBS=-lssl)
AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent, exit 1)
AC_CHECK_LIB(argp, argp_parse, ARGP_LIBS=-largp)
AC_CHECK_LIB(socket, bind, SOCKET_LIBS=-lsocket)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------
AC_CHECK_FUNCS(sendfile strnlen daemon)

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

PKG_PROG_PKG_CONFIG()

AM_PATH_GLIB_2_0(2.0.0, , exit 1, gthread)
AM_PATH_XML2(2.6.0, , exit 1)

AC_SUBST(CRYPTO_LIBS)
AC_SUBST(SSL_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(ARGP_LIBS)
AC_SUBST(SOCKET_LIBS)

AC_CONFIG_FILES([doc/Makefile
		 lib/Makefile
		 lib/libchunkdc.pc
		 lib/libchunkdc-uninstalled.pc
		 include/Makefile
		 server/Makefile
		 test/Makefile
		 Makefile])
AC_OUTPUT

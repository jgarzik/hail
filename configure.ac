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

m4_define([libhail_major_version], [1])
m4_define([libhail_minor_version], [1])
m4_define([libhail_micro_version], [1])
m4_define([libhail_interface_age], [1])
# If you need a modifier for the version number. 
# Normally empty, but can be used to make "fixup" releases.
m4_define([libhail_extraversion], [])

dnl libtool versioning from libhail
m4_define([libhail_current], [m4_eval(100 * libhail_minor_version + libhail_micro_version - libhail_interface_age)])
m4_define([libhail_binary_age], [m4_eval(100 * libhail_minor_version + libhail_micro_version)])
m4_define([libhail_revision], [libhail_interface_age])
m4_define([libhail_age], [m4_eval(libhail_binary_age - libhail_interface_age)])
m4_define([libhail_version], [libhail_major_version().libhail_minor_version().libhail_micro_version()libhail_extraversion()])

AC_INIT([hail], [0.7git],
        [http://hail.wiki.kernel.org/])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([cld/server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([hail-config.h])

LIBHAIL_MAJOR_VERSION=libhail_major_version
LIBHAIL_MINOR_VERSION=libhail_minor_version
LIBHAIL_MICRO_VERSION=libhail_micro_version
LIBHAIL_INTERFACE_AGE=libhail_interface_age

LIBHAIL_CURRENT=libhail_current
LIBHAIL_REVISION=libhail_revision
LIBHAIL_AGE=libhail_age

AC_SUBST(LIBHAIL_CURRENT)
AC_SUBST(LIBHAIL_REVISION)
AC_SUBST(LIBHAIL_AGE)

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)
AC_CHECK_HEADERS(sys/sendfile.h sys/filio.h)
AC_CHECK_HEADER(db.h,[],exit 1)

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_CHECK_LIB(db-5.0, db_create, DB4_LIBS=-ldb-5.0,
	AC_CHECK_LIB(db-4.9, db_create, DB4_LIBS=-ldb-4.9,
	AC_CHECK_LIB(db-4.8, db_create, DB4_LIBS=-ldb-4.8,
	AC_CHECK_LIB(db-4.7, db_create, DB4_LIBS=-ldb-4.7,
	AC_CHECK_LIB(db-4.6, db_create, DB4_LIBS=-ldb-4.6,
	AC_CHECK_LIB(db-4.5, db_create, DB4_LIBS=-ldb-4.5,
	AC_CHECK_LIB(db-4.4, db_create, DB4_LIBS=-ldb-4.4,
	AC_CHECK_LIB(db-4.3, db_create, DB4_LIBS=-ldb-4.3,
  [AC_MSG_ERROR([Missing required libdb 4.x])]))))))))
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto)
AC_CHECK_LIB(ssl, SSL_new, SSL_LIBS=-lssl)
AC_SEARCH_LIBS(argp_parse, argp)
AC_SEARCH_LIBS(bind, socket)
AC_SEARCH_LIBS(dn_expand, resolv)
AC_SEARCH_LIBS(ns_initparse, resolv)
PKG_CHECK_MODULES(FUSE, fuse)
PKG_CHECK_MODULES(TOKYOCABINET, tokyocabinet)


dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------
AC_CHECK_FUNCS(strnlen daemon memmem memrchr sendfile)

case $host in
  *-*-solaris* )
     AC_DEFINE(_XOPEN_SOURCE_EXTENDED, 1, Needed to get declarations for msg_control and msg_controllen on Solaris)
     AC_DEFINE(_XOPEN_SOURCE,          2, Needed to get declarations for msg_control and msg_controllen on Solaris)
     AC_DEFINE(__EXTENSIONS__,         1, Needed to get declarations for msg_control and msg_controllen on Solaris)
     ;;
esac

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

PKG_PROG_PKG_CONFIG()

AM_PATH_GLIB_2_0(2.0.0,,,gthread)
AM_PATH_XML2(2.6.0, , exit 1)

AC_SUBST(DB4_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(SSL_LIBS)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	lib/Makefile
	lib/libhail.pc
	lib/libhail-uninstalled.pc
	include/Makefile
	cld/Makefile
	chunkd/Makefile
	test/Makefile
	test/cld/Makefile
	test/chunkd/Makefile
	test/chunkd/start-daemon.real
	tools/Makefile])
AC_OUTPUT

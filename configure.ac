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

m4_define([libcldc_major_version], [1])
m4_define([libcldc_minor_version], [1])
m4_define([libcldc_micro_version], [1])
m4_define([libcldc_interface_age], [1])
# If you need a modifier for the version number. 
# Normally empty, but can be used to make "fixup" releases.
m4_define([libcldc_extraversion], [])

dnl libtool versioning from libcldc
m4_define([libcldc_current], [m4_eval(100 * libcldc_minor_version + libcldc_micro_version - libcldc_interface_age)])
m4_define([libcldc_binary_age], [m4_eval(100 * libcldc_minor_version + libcldc_micro_version)])
m4_define([libcldc_revision], [libcldc_interface_age])
m4_define([libcldc_age], [m4_eval(libcldc_binary_age - libcldc_interface_age)])
m4_define([libcldc_version], [libcldc_major_version().libcldc_minor_version().libcldc_micro_version()libcldc_extraversion()])

AC_INIT([cld], [0.2.1],
        [http://hail.wiki.kernel.org/])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([server/server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([cld-config.h])

LIBCLDC_MAJOR_VERSION=libcldc_major_version
LIBCLDC_MINOR_VERSION=libcldc_minor_version
LIBCLDC_MICRO_VERSION=libcldc_micro_version
LIBCLDC_INTERFACE_AGE=libcldc_interface_age

LIBCLDC_CURRENT=libcldc_current
LIBCLDC_REVISION=libcldc_revision
LIBCLDC_AGE=libcldc_age

AC_SUBST(LIBCLDC_CURRENT)
AC_SUBST(LIBCLDC_REVISION)
AC_SUBST(LIBCLDC_AGE)

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AM_PROG_LIBTOOL

dnl Checks for header files.
dnl AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)
AC_CHECK_HEADER(db.h,[],exit 1)

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_CHECK_LIB(db-4.7, db_create, DB4_LIBS=-ldb-4.7,
	AC_CHECK_LIB(db-4.6, db_create, DB4_LIBS=-ldb-4.6,
	AC_CHECK_LIB(db-4.5, db_create, DB4_LIBS=-ldb-4.5,
	AC_CHECK_LIB(db-4.4, db_create, DB4_LIBS=-ldb-4.4,
	AC_CHECK_LIB(db-4.3, db_create, DB4_LIBS=-ldb-4.3, exit 1)))))
AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent, exit 1)
AC_CHECK_LIB(argp, argp_parse, ARGP_LIBS=-largp)
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------
AC_CHECK_FUNCS(strnlen daemon memmem memrchr)

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

AC_SUBST(DB4_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(ARGP_LIBS)
AC_SUBST(CRYPTO_LIBS)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	lib/Makefile
	lib/libcldc.pc
	lib/libcldc-uninstalled.pc
	include/Makefile
	server/Makefile
	test/Makefile
	tools/Makefile])
AC_OUTPUT

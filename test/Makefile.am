
INCLUDES	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@

EXTRA_DIST =			\
	test.h			\
	prep-db			\
	start-daemon		\
	pid-exists		\
	stop-daemon		\
	clean-db

TESTS =			\
	prep-db			\
	start-daemon		\
	pid-exists		\
	basic-session		\
	basic-io		\
	lock-file		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-session \
			  basic-io	\
			  lock-file

TESTLDADD		= ../lib/libhail.la	\
			  @GLIB_LIBS@ @CRYPTO_LIBS@
basic_session_LDADD	= $(TESTLDADD)
basic_io_LDADD		= $(TESTLDADD)
lock_file_LDADD		= $(TESTLDADD)

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

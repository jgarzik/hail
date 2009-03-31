
INCLUDES        = -I$(top_srcdir)/include       \
		  @GLIB_CFLAGS@

EXTRA_DIST =			\
	prep-db			\
	start-daemon		\
	pid-exists		\
	stop-daemon		\
	clean-db

TESTS =				\
	prep-db			\
	start-daemon		\
	pid-exists		\
	it-works		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= it-works

TESTLDADD		= ../lib/libcldc.la	\
			  @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@
it_works_LDADD		= $(TESTLDADD)


TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

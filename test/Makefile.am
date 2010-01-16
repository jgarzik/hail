
INCLUDES        = -I$(top_srcdir)/include       \
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
	it-works		\
	save-file-event		\
	load-file-event		\
	lock-file-event		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= it-works \
			  save-file-event load-file-event lock-file-event

TESTLDADD		= ../lib/libcldc.la	\
			  libtest.a		\
			  @GLIB_LIBS@ @CRYPTO_LIBS@
it_works_LDADD		= $(TESTLDADD)
save_file_event_LDADD	= $(TESTLDADD)
load_file_event_LDADD	= $(TESTLDADD)
lock_file_event_LDADD	= $(TESTLDADD)

noinst_LIBRARIES	= libtest.a

libtest_a_SOURCES	= util.c

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

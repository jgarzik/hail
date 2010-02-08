
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
	save-file-event		\
	load-file-event		\
	lock-file-event		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-session \
			  save-file-event load-file-event lock-file-event

TESTLDADD		= ../lib/libcldc.la	\
			  @GLIB_LIBS@ @CRYPTO_LIBS@
basic_session_LDADD	= $(TESTLDADD)
save_file_event_LDADD	= $(TESTLDADD)
load_file_event_LDADD	= $(TESTLDADD)
lock_file_event_LDADD	= $(TESTLDADD)

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

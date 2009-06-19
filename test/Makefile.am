
INCLUDES        = -I$(top_srcdir)/include       \
		  @GLIB_CFLAGS@

EXTRA_DIST =			\
	prep-db			\
	start-daemon		\
	pid-exists		\
	stop-daemon		\
	clean-db

#TESTS =			\
#	prep-db			\
#	start-daemon		\
#	pid-exists		\
#	it-works		\
#	save-file-event		\
#	load-file-event		\
#	lock-file-event		\
#	stop-daemon		\
#	clean-db
TESTS =				\
	prep-db			\
	start-daemon		\
	pid-exists		\
	it-works		\
	stop-daemon		\
	clean-db

#check_PROGRAMS		= it-works \
#			  save-file-event load-file-event lock-file-event
check_PROGRAMS		= it-works

TESTLDADD		= ../lib/libcldc.la	\
			  @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@
it_works_LDADD		= $(TESTLDADD)
#save_file_event_LDADD	= $(TESTLDADD)
#load_file_event_LDADD	= $(TESTLDADD)
#lock_file_event_LDADD	= $(TESTLDADD)


TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

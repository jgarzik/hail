
INCLUDES	= -I$(top_srcdir)/include	\
		  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	server-test.cfg		\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	stop-daemon		\
	clean-db

TESTS =				\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	it-works		\
	basic-object		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-object it-works

TESTLDADD		= ../lib/libstc.a	\
			  ../lib/libhttputil.a	\
			  @PCRE_LIBS@ @LIBCURL@ @GLIB_LIBS@ @CRYPTO_LIBS@ \
			  @XML_LIBS@
basic_object_LDADD	= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)


INCLUDES	= -I$(top_srcdir)/include	\
		  @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	server-test.cfg		\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	stop-daemon		\
	clean-db		\
	ssl-key.pem ssl-cert.pem

TESTS =				\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	it-works		\
	basic-object		\
	large-object		\
	lotsa-objects		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-object it-works large-object \
			  lotsa-objects

TESTLDADD		= ../lib/libstc.a	\
			  @GLIB_LIBS@ @CRYPTO_LIBS@ \
			  @XML_LIBS@ @SSL_LIBS@
basic_object_LDADD	= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)
large_object_LDADD	= $(TESTLDADD)
lotsa_objects_LDADD	= $(TESTLDADD)

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

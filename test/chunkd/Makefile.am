
INCLUDES	= -I$(top_srcdir)/include	\
		  -I$(top_srcdir)/lib		\
		  @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	server-test.cfg		\
	prep-db			\
	start-daemon		\
	start-daemon.real	\
	pid-exists		\
	daemon-running		\
	stop-daemon		\
	clean-db		\
	ssl-key.pem ssl-cert.pem

TESTS =				\
	objcache-unit		\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	it-works		\
	nop			\
	basic-object		\
	auth			\
	cp			\
	large-object		\
	lotsa-objects		\
	selfcheck-unit		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= auth basic-object cp it-works large-object \
			  lotsa-objects nop objcache-unit selfcheck-unit

TESTLDADD		= ../../lib/libhail.la	\
			  libtest.a		\
			  @GLIB_LIBS@ @CRYPTO_LIBS@ \
			  @XML_LIBS@ @SSL_LIBS@
basic_object_LDADD	= $(TESTLDADD)
cp_LDADD		= $(TESTLDADD)
auth_LDADD		= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)
large_object_LDADD	= $(TESTLDADD)
lotsa_objects_LDADD	= $(TESTLDADD)
nop_LDADD		= $(TESTLDADD)
selfcheck_unit_LDADD	= $(TESTLDADD)

objcache_unit_LDADD	= @GLIB_LIBS@

noinst_LIBRARIES	= libtest.a

libtest_a_SOURCES	= libtest.c

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

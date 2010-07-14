Name:		hail
Version:	0.8
Release:	0.2.gf9c5b967%{?dist}
Summary:	Project Hail core cloud services

Group:		System Environment/Libraries
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit f9c5b967cb409cb3e38870b21292374ccea3ee6e
# to recreate tarball, check out commit, then run "make dist"
Source0:	hail-%{version}git.tar.gz

# cld, chunkd init.d and sysconfig data.  copied from pkg/* in upstream git,
# commit 554f1338e29342ba6dcfa0bce648d304afc2c1e1
Source2:	cld.init
Source3:	cld.sysconf
Source4:	chunkd.init
Source5:	chunkd.sysconf

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	db4-devel glib2-devel doxygen openssl-devel
BuildRequires:	texlive-latex fuse-devel libcurl-devel
BuildRequires:	libxml2-devel procps tokyocabinet-devel

%description
Core libraries and document associated with cloud computing related
Project Hail.

%package -n cld
Summary: Coarse locking service for %{name}
Group: System Environment/Base
Requires: %{name} = %{version}-%{release}
Requires(post):		chkconfig
Requires(preun):	chkconfig initscripts

%description -n cld
Coarse locking daemon for cloud computing.  This software provides
a cache-coherent, highly-available distributed file system for small
files.

CLD's primary uses include consensus service (election of a master,
with fail-over, also known as lock service), reliable name space,
and reliable small file storage.

%package -n chunkd
Summary: Single-node data storage service for %{name}
Group: System Environment/Base
Requires: %{name} = %{version}-%{release}
Requires(post):		chkconfig
Requires(preun):	chkconfig initscripts

%description -n chunkd
Single-node data storage daemon for cloud computing.

This TCP network service is a very simple PUT/GET/DELETE data storage
service.  It is intended to be used as a low-level piece of large-scale
distributed data storage infrastructure.  The service provides
operations on stored data ("objects").

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig openssl-devel glib2-devel
Conflicts: cld-devel chunkd-devel

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n hail-0.8git

%build
%configure --disable-static
make %{?_smp_mflags}
rm -rf gendoc && mkdir gendoc && doxygen
( cd gendoc/latex && make )

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE2} %{buildroot}%{_initddir}/cld

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/cld

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE4} %{buildroot}%{_initddir}/chunkd

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE5} %{buildroot}%{_sysconfdir}/sysconfig/chunkd

mkdir -p %{buildroot}%{_libdir}/cld/lib

find %{buildroot} -name '*.la' -exec rm -f {} ';'

%check
make -s check

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%post -n cld
# must be in chkconfig on
/sbin/chkconfig --add cld

%post -n chunkd
# must be in chkconfig on
/sbin/chkconfig --add chunkd

%preun -n cld
if [ "$1" = 0 ] ; then
	/sbin/service cld stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del cld
fi

%preun -n chunkd
if [ "$1" = 0 ] ; then
	/sbin/service chunkd stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del chunkd
fi

%postun -p /sbin/ldconfig

%postun -n cld
if [ "$1" -ge "1" ]; then
	/sbin/service cld condrestart >/dev/null 2>&1 ||:
fi

%postun -n chunkd
if [ "$1" -ge "1" ]; then
	/sbin/service chunkd condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING LICENSE README NEWS doc/contributions.txt
%{_libdir}/*.so.*

%files -n cld
%defattr(-,root,root,-)
%{_sbindir}/cld
%{_bindir}/cldcli
%{_mandir}/man8/cldcli.8*
%{_mandir}/man8/cld.8*
%{_libdir}/cld
%attr(0755,root,root)	%{_initddir}/cld
%config(noreplace)	%{_sysconfdir}/sysconfig/cld

%files -n chunkd
%defattr(-,root,root,-)
%doc doc/api.txt doc/cfgfile.txt doc/chcli.cfg doc/chcli.txt
%doc doc/concept.txt doc/logging.txt
%{_sbindir}/chunkd
%{_bindir}/chcli
%{_mandir}/man8/chcli.8*
%{_mandir}/man8/chunkd.8*
%attr(0755,root,root)	%{_initddir}/chunkd
%config(noreplace)	%{_sysconfdir}/sysconfig/chunkd

%files devel
%defattr(-,root,root,-)
%doc gendoc/html gendoc/latex/refman.pdf
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Wed Jul 14 2010 Jeff Garzik <jgarzik@redhat.com> - 0.8-0.2.gf9c5b967
- Update to upstream commit f9c5b967cb409cb3e38870b21292374ccea3ee6e

* Tue Jul 13 2010 Jeff Garzik <jgarzik@redhat.com> - 0.8-0.1.gee257f18
- Update to upstream commit ee257f18f601922df84687736c6bd1ac76b16580

* Fri Jul  2 2010 Jeff Garzik <jgarzik@redhat.com> - 0.7-1
- Initial release.


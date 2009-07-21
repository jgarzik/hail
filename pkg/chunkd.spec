Name:		chunkd
Version:	0.4
Release:	0.3.g5f69efd9%{?dist}
Summary:	Data storage daemon for cloud computing

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit 5f69efd93fb6dc0c2e9882cd3c22cc096eede486
# to recreate tarball, check out commit, then run "make dist"
Source0:	chunkd-%{version}git.tar.gz
Source2:	chunkd.init
Source3:	chunkd.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# N.B. We need cld to build, because our "make check" spawns a private copy.
BuildRequires:	libevent-devel glib2-devel openssl-devel zlib-devel
BuildRequires:	libxml2-devel procps cld cld-devel

# cld is broken on big-endian... embarrassing!!!
# FIXME: remove this when cld is fixed
ExcludeArch: ppc ppc64

%description
Single-node data storage daemon for cloud computing.

This TCP network service is a very simple PUT/GET/DELETE data storage
service.  It is intended to be used as a low-level piece of large-scale
distributed data storage infrastructure.  The service provides
operations on stored data ("objects").

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n %{name}-%{version}git


%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE2} %{buildroot}%{_initddir}/chunkd

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/chunkd

find %{buildroot} -name '*.la' -exec rm -f {} ';'

%check
make check

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
# must be in chkconfig on
/sbin/chkconfig --add chunkd

%preun
if [ "$1" = 0 ] ; then
	/sbin/service chunkd stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del chunkd
fi

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
	/sbin/service chunkd condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING LICENSE README NEWS doc/*.txt
%{_sbindir}/chunkd
%{_libdir}/*.so.*
%attr(0755,root,root)	%{_initddir}/chunkd
%config(noreplace)	%{_sysconfdir}/sysconfig/chunkd

%files devel
%defattr(-,root,root,-)
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.3.g5f69efd9
- update source to commit 5f69efd93fb6dc0c2e9882cd3c22cc096eede486

* Sun Jul 19 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.2.ge073b822
- update source to commit e073b82297fc3c88f94f524c82e9e6e86fb2cd0a
- improve pkg description
- per pkg guidelines, describe how to regen source tarball from git
- add doc LICENSE

* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.1.g6f54181c
- kill RPM_BUILD_ROOT
- new release version scheme

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-4%{?dist}
- chkconfig default off
- add doc: COPYING
- config(noreplace) sysconfig/chunkd

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-3%{?dist}
- minor spec updates for review feedback, Fedora packaging guidelines

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-2%{?dist}
- updated BuildRequires
- rpmlint fixes
- updated to latest git repo

* Fri May 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-1%{?dist}
- Version 0.3

* Fri May 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2-1%{?dist}
- Version 0.2

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2git-2%{?dist}
- package and ship libchunkdc

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2git-1%{?dist}
- initial release


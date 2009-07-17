Name:		cld
Version:	0.2git
Release:	1%{?dist}
Summary:	Coarse locking daemon

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git
Source0:	cld-%{version}.tar.gz
Source2:	cld.init
Source3:	cld.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	db4-devel libevent-devel glib2-devel doxygen openssl-devel
BuildRequires:	texlive-latex

# cld is broken on big-endian... embarrassing!!!
# FIXME: remove this when cld is fixed
ExcludeArch: ppc ppc64

%description
Coarse locking daemon.

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q

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

find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%check
make -s check

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
# must be in chkconfig on
/sbin/chkconfig --add cld

%preun
if [ "$1" = 0 ] ; then
	/sbin/service cld stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del cld
fi

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
	/sbin/service cld condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING LICENSE README NEWS doc/*.txt
%{_sbindir}/cld
%{_sbindir}/cldbadm
%{_libdir}/*.so.*
%attr(0755,root,root)	%{_initddir}/cld
%config(noreplace)	%{_sysconfdir}/sysconfig/cld

%files devel
%defattr(-,root,root,-)
%doc gendoc/html gendoc/latex/refman.pdf
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2git-1
- git snapshot immediately following 0.1 release

* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1-1
- version 0.1 release

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-5
- chkconfig default off
- add doc: COPYING, LICENSE
- config(noreplace) sysconfig/cld

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-4
- minor spec updates for review feedback, Fedora packaging guidelines

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-3
- update BuildRequires
- rpmlint fixes
- update to latest git repo

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-2
- update cld initscript

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-1.libtest
- initial release


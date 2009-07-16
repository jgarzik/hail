Name:		cld
Version:	0.1git
Release:	3%{?dist}
Summary:	Coarse locking daemon

Group:		System Environment/Base
License:	GPLv2
URL:		http://www.kernel.org/pub/software/network/distsrv/
Source0:	cld-0.1git.tar.gz
Source2:	cld.init
Source3:	cld.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	db4-devel libevent-devel glib2-devel doxygen openssl-devel
BuildRequires:	texlive-latex

%description
Coarse locking daemon.

%package devel
Summary: Header files, libraries and development documentation for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
This package contains the header files, static libraries and development
documentation for %{name}. If you like to develop programs using %{name},
you will need to install %{name}-devel.

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}
rm -rf gendoc && mkdir gendoc && doxygen
( cd gendoc/latex && make )

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
install -m 755 %{SOURCE2} %{buildroot}%{_sysconfdir}/rc.d/init.d/cld

mkdir -p %{buildroot}/etc/sysconfig
install -m 755 %{SOURCE3} %{buildroot}/etc/sysconfig/cld

%check
make -s check

%clean
rm -rf $RPM_BUILD_ROOT

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
%doc README NEWS doc/*.txt
%{_sbindir}/cld
%{_sbindir}/cldbadm
%{_libdir}/lib*.so.*
%attr(0755,root,root)	%{_sysconfdir}/rc.d/init.d/cld
%attr(0644,root,root)	%{_sysconfdir}/sysconfig/cld

%files devel
%defattr(-,root,root,-)
%doc gendoc/html gendoc/latex/refman.pdf
%{_libdir}/lib*.so
%{_libdir}/lib*.a
%{_libdir}/lib*.la
%{_libdir}/pkgconfig/*
%{_includedir}/*.h

%changelog
* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-3
- update BuildRequires
- rpmlint fixes
- update to latest git repo

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-2
- update cld initscript

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-1.libtest
- initial release


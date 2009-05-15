Name:           chunkd
Version:        0.3git
Release:        1%{?dist}
Summary:        Data storage daemon

Group:          System Environment/Base
License:        GPLv2
URL:            http://www.kernel.org/pub/software/network/distsrv/
Source0:        chunkd-%{version}.tar.gz
Source2:        chunkd.init
Source3:        chunkd.sysconf
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  db4-devel libevent-devel glib2-devel

%description
Data storage daemon.

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


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
install -m 755 %{SOURCE2} %{buildroot}%{_sysconfdir}/rc.d/init.d/chunkd

mkdir -p %{buildroot}/etc/sysconfig
install -m 755 %{SOURCE3} %{buildroot}/etc/sysconfig/chunkd

%check
make check

%clean
rm -rf $RPM_BUILD_ROOT

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
%doc README NEWS doc/*.txt
%{_sbindir}/chunkd
%{_libdir}/lib*.so.*
%attr(0755,root,root)           %{_sysconfdir}/rc.d/init.d/chunkd
%attr(0644,root,root)           %{_sysconfdir}/sysconfig/chunkd

%files devel
%defattr(-,root,root,0644)
%{_libdir}/lib*.so
%{_libdir}/lib*.a
%{_libdir}/lib*.la
%{_libdir}/pkgconfig/*
%{_includedir}/*.h

%changelog
* Fri May 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-1%{?dist}
- Bump version to 0.3git

* Fri May 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2-1%{?dist}
- Version 0.2

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2git-2%{?dist}
- package and ship libchunkdc

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.2git-1%{?dist}
- initial release


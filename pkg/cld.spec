Name:           cld
Version:        0.1git
Release:        1.1c47583%{?dist}
Summary:        Coarse locking daemon

Group:          System Environment/Base
License:        GPLv2
URL:            http://www.kernel.org/pub/software/network/distsrv/
Source0:        cld-0.1git.1c47583.tar.gz
Source2:	cld.init
Source3:	cld.sysconf
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  db4-devel libevent-devel glib2-devel
Requires:       db4 libevent glib2

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


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
install -m 755 %{SOURCE2} %{buildroot}%{_sysconfdir}/rc.d/init.d/atd

mkdir -p %{buildroot}/etc/sysconfig
install -m 755 %{SOURCE3} %{buildroot}/etc/sysconfig/atd

%check
make check

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README NEWS doc/*.txt
%{_sbindir}/cld
%attr(0755,root,root)		%{_sysconfdir}/rc.d/init.d/atd
%attr(0644,root,root)		%{_sysconfdir}/sysconfig/atd
%doc README

%files devel
%defattr(-,root,root,0644)
%{_includedir}/cldc.h
%{_includedir}/cld_msg.h

%changelog
* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.1git-1.1c47583
- initial release


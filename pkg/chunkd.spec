Name:		chunkd
Version:	0.3
Release:	4%{?dist}
Summary:	Data storage daemon

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit ccc1d96852d0b7c701dbc3aa5cf6d9fae90f1d25
Source0:	chunkd-%{version}.tar.gz
Source2:	chunkd.init
Source3:	chunkd.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	libevent-devel glib2-devel openssl-devel zlib-devel
BuildRequires:	libxml2-devel procps

# cld is broken on big-endian... embarrassing!!!
# FIXME: remove this when cld is fixed
ExcludeArch: ppc ppc64

%description
Data storage daemon.

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


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE2} %{buildroot}%{_initddir}/chunkd

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/chunkd

find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

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
%doc AUTHORS COPYING README NEWS doc/*.txt
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


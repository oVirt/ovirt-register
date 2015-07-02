%if 0%{?fedora} || 0%{?rhel} >= 7
%global with_systemd 1
%endif

%if 0%{?fedora} || 0%{?rhel} >= 8
%global with_python3 1
%else
%global with_python2 1
%endif

%{!?__python2: %global __python2 /usr/bin/python2}
%{!?py2dir: %global py2dir %{_builddir}/%{name}-%{version}}
%{!?python2_sitelib2: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}

%global modname ovirt_register

Name:           python-ovirt-register
Version:        1.0
Release:        3%{?dist}
Summary:        A python module and tool for registering nodes to oVirt Engine
License:        GPLv2+
Group:          System Environment/Libraries
URL:            https://github.com/dougsland/ovirt-register/wiki
Source0:        https://github.com/dougsland/ovirt-register/raw/master/%{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools

%if 0%{?with_python3}
BuildRequires: python3-devel
BuildRequires: python3-setuptools
%endif

Requires: pyOpenSSL
Requires: dmidecode
Requires: python-requests
Requires: libselinux-python
%if 0%{?with_systemd}
Requires: systemd-python
%endif

%{!?_licensedir:%global license %%doc}

%description
python ovirt register is a python 2 library for registering hosts
to oVirt Engine via HTTPs protocol. It supports Engine 3.3 or superior.
This package also contains the command line tool ovirt-register to
trigger the registration.

%if 0%{?with_python3}
%package -n python3-ovirt-register
Summary: A python 3 module and tool for registering nodes to oVirt Engine
Requires: dmidecode
Requires: python3-pyOpenSSL
Requires: python3-requests
Requires: systemd-python3
Requires: libselinux-python3

%description -n python3-ovirt-register
python ovirt register is a python 3 library for registering hosts
to oVirt Engine via HTTPs protocol. It supports Engine 3.3 or superior.
This package also contains the command line tool ovirt-register to
trigger the registration.
%endif

%prep
%setup -q -n %{name}-%{version}

%if 0%{?with_python3}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif

%build
%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py build
popd
%endif

%if 0%{?with_python2}
pushd %{py2dir}
%{__python2} setup.py build
popd
%endif


%install
%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py install --skip-build --root %{buildroot}
popd
%endif

%if 0%{?with_python2}
pushd %{py2dir}
%{__python2} setup.py install --skip-build --root %{buildroot}
popd
%endif

# install man page
install -p -d -m755 %{buildroot}%{_mandir}/man1
install -p -m644 man/ovirt-register.1 %buildroot%{_mandir}/man1/ovirt-register.1

%if 0%{?with_python2}
%files
%doc AUTHORS docs/PROTOCOL docs/README
%license COPYING
%dir %{python2_sitelib}/%{modname}
%{python2_sitelib}/%{modname}/*
%{python2_sitelib}/*.egg-info
%{_bindir}/ovirt-register
%{_mandir}/man1/ovirt-register.1.gz
%endif

%if 0%{?with_python3}
%files -n python3-ovirt-register
%doc AUTHORS docs/PROTOCOL docs/README
%license COPYING
%dir %{python3_sitelib}/%{modname}
%{python3_sitelib}/%{modname}/*
%{python3_sitelib}/*.egg-info
%{_bindir}/ovirt-register
%{_mandir}/man1/ovirt-register.1.gz
%endif

%changelog
* Thu Jul 02 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-3
- Improve uuid API handling
- improve spec
- try/except to syslog

* Thu Jul 02 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-2
- Improvements in docstring, persist_uuid and pki module

* Wed Jun 24 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-1
- Support registration for Engine 3.3 or higher
- Split package for python2 and python3
- Improve persist/unpersist handling
- Improve uuid handling
- Improve logging

* Thu May 07 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-0
- Initial take

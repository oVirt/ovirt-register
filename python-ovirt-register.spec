%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%global libname ovirtregister

Name:           python-ovirt-register
Version:        1.0
Release:        1%{?dist}
Summary:        A python module for registering nodes to oVirt Engine

License:        GPLv2+
Group:          System Environment/Libraries
URL:            https://github.com/dougsland/ovirt-register/wiki
Source0:        https://github.com/dougsland/ovirt-register/raw/master/%{name}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires: dmidecode
Requires: python-requests

BuildRequires: python2-devel
BuildRequires: python-setuptools

%description
Python script/module to register a host into oVirt Engine

%prep
%setup -q -n %{name}-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root %{buildroot}
# install man page
install -p -d -m755 %{buildroot}%{_mandir}/man1
install -p -m644 man/ovirt-register.1 %buildroot%{_mandir}/man1/ovirt-register.1

%files
%defattr(-,root,root,-)
%doc AUTHORS docs/PROTOCOL
%{!?_licensedir:%global license %%doc}
%license COPYING
%{python_sitelib}/%{libname}/__init__.py*
%{python_sitelib}/%{libname}/operations.py*
%{python_sitelib}/%{libname}/register.py*
%{python_sitelib}/%{libname}/system.py*
%{_bindir}/ovirt-register
%{_mandir}/man1/ovirt-register.1*
%if (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{python_sitelib}/*.egg-info
%endif

%changelog
* Wed Jun 24 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-1
- Support registration for Engine 3.3 or higher

* Thu May 07 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-0
- Initial take

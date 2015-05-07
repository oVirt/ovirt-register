%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%global libname ovirtnoderegister

Name:           python-ovirt-node-register
Version:        1.0
Release:        0%{?dist}
Summary:        A python module for registering nodes to oVirt Engine

License:        GPLv2+
Group:          System Environment/Libraries
URL:            https://github.com/dougsland/ovirt-node-register/wiki
Source0:        https://github.com/dougsland/ovirt-node-register/raw/master/%{name}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires: python-requests
Requires: m2crypto

BuildRequires: python2-devel
BuildRequires: python-setuptools

%description
Python module for turning an OS into a oVirt Engine node

%prep
%setup -q -n %{name}-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root %{buildroot}

%files
%defattr(-,root,root,-)
%doc COPYING
%{!?_licensedir:%global license %%doc}
%license COPYING
%{python_sitelib}/%{libname}/__init__.py*
%{python_sitelib}/%{libname}/expts.py*
%{python_sitelib}/%{libname}/log.py*
%{python_sitelib}/%{libname}/operations.py*
%{python_sitelib}/%{libname}/register.py*
%{python_sitelib}/%{libname}/system.py*
%{_bindir}/ovirt-node-register
%if (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{python_sitelib}/*.egg-info
%endif

%changelog
* Thu May 07 2015 Douglas Schilling Landgraf <dougsland@redhat.com> 1.0-0
- Initial take

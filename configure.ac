# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# copy-pasted from libreport/abrt
# CONF_PARSE_WITH(PACKAGE)
# -----------------------
# For use in AC_ARG_WITH action-if-found, for packages default ON.
# * Set NO_PACKAGE=YesPlease for --without-PACKAGE
# * Unset NO_PACKAGE for --with-PACKAGE without ARG
AC_DEFUN([CONF_PARSE_WITH],
    [m4_pushdef([CONF_UC_PACKAGE], m4_toupper([$1]))dnl
    if test "$withval" = "no"; then
        NO_[]CONF_UC_PACKAGE=YesPlease
    elif test "$withval" = "yes"; then
        NO_[]CONF_UC_PACKAGE=
    else
        NO_[]CONF_UC_PACKAGE=
    fi
    m4_popdef([CONF_UC_PACKAGE])])

define([VERSION_MAJOR], [1])
define([VERSION_MINOR], [0])
define([VERSION_FIX], [0])
define([VERSION_NUMBER], VERSION_MAJOR[.]VERSION_MINOR[.]VERSION_FIX)
define([VERSION_SUFFIX], [])

AC_INIT([python-ovirt-register], VERSION_NUMBER[]VERSION_SUFFIX, [devel@ovirt.org])
PACKAGE_NAME="python-ovirt-register"
PACKAGE_RPM_VERSION="VERSION_NUMBER"
PACKAGE_RPM_RELEASE="5"
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability tar-pax])
AC_SUBST([PACKAGE_RPM_VERSION])
AC_SUBST([PACKAGE_RPM_RELEASE])

AC_PROG_INSTALL
AC_PROG_SED
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_ARG_WITH(python3,
AS_HELP_STRING([--with-python3],[build Python3 support (default is YES)]),
CONF_PARSE_WITH([python3]))

[if test -z "$NO_PYTHON3"]
[then]
    AM_CONDITIONAL(BUILD_PYTHON3, true)
    AC_PATH_PROG([PYTHON3], [python3], [no])
    [if test "$PYTHON3" == "no"]
    [then]
        [echo "The python3 program was not found in the search path. Please ensure"]
        [echo "that it is installed and its directory is included in the search path or"]
        [echo "pass --without-python3 to ./configure."]
        [echo "Then run configure again before attempting to build."]
        [exit 1]
    [fi]

    AC_SUBST([PYTHON3_PREFIX], ['${prefix}'])
    AC_SUBST([PYTHON3_EXEC_PREFIX], ['${exec_prefix}'])

    PYTHON3_DIR=`$PYTHON3 -c "import distutils.sysconfig; \
        print(distutils.sysconfig.get_python_lib(0,0,prefix='$PYTHON3_PREFIX'))"`
    PYTHON3_EXECDIR=`$PYTHON3 -c "import distutils.sysconfig; \
        print(distutils.sysconfig.get_python_lib(1,0,prefix='$PYTHON3_EXEC_PREFIX'))"`

    AC_SUBST(PYTHON3_CFLAGS)
    AC_SUBST(PYTHON3_LIBS)
    AC_SUBST(python3dir, $PYTHON3_DIR)
    AC_SUBST(py3execdir, $PYTHON3_EXECDIR)
    AC_SUBST([regpythonlibdir], ["\$(python3dir)/ovirt_register"])
[else]
    AM_CONDITIONAL(BUILD_PYTHON3, false)
    AM_PATH_PYTHON([2])
    AC_SUBST([regpythonlibdir], ["\$(pythondir)/ovirt_register"])
[fi]

# Python tools
AC_ARG_VAR([PEP8], [pep8 utility])
AC_CHECK_PROGS([PEP8], [pep8])
AC_ARG_VAR([PYFLAKES], [pyflakes utility])
AC_CHECK_PROGS([PYFLAKES], [pyflakes])

# External programs
AC_PATH_PROG([DMIDECODE_PATH], [dmidecode], [/usr/sbin/dmidecode])



AC_CONFIG_FILES([
		Makefile
		src/Makefile
		src/ovirt_register/Makefile
		src/scripts/Makefile
		man/Makefile
                docs/Makefile
		python-ovirt-register.spec])
AC_OUTPUT

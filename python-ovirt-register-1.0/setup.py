# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
# Douglas Schilling Landgraf <dougsland@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from distutils.core import setup

setup(name='ovirt-register',
      version='1.0',
      description='A python module for registering nodes to oVirt Engine',
      author='Douglas Schilling Landgraf',
      author_email='dougsland@redhat.com',
      url='https://github.com/dougsland/ovirt-register/wiki',
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: GPLv2+',
          'Programming Language :: Python',
          ],
      license= 'GPLv2+',
      packages=['ovirt_register'],
      scripts = ['scripts/ovirt-register'])

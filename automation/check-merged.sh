#!/bin/bash -xe
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

# If it's Fedora use python3
if [ -f "/etc/fedora-release" ]
then
    ./autogen.sh
else
    ./autogen.sh --without-python3
fi

make -j8 check-local

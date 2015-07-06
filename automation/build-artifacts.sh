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

shopt -s nullglob

rm -rf ../exported-artifacts/*
rm -rf tmp.repos
# generate automake/autoconf files
./autogen.sh

# create rpm
make rpm
mkdir -p ../exported-artifacts/

for file in $(find tmp.repos -iregex ".*\.\(tar\.gz\|rpm\)$"); do
    echo "Archiving $file"
    mv "$file" ../exported-artifacts/
done

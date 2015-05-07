#!/usr/bin/python
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


class Error(Exception):
    """
    Base class for exceptions
    """
    pass


class FingerprintError(Error):
    """Exception raised during error comparing fingerprints.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class StatesError(Error):
    """Exception raised when no state is set to be run

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

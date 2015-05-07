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
import sys
import logging


class Log(object):

    def start(self):
        """
        The logging settings
        Saving log in: /var/log/register.log
        """
        logging.basicConfig(
            filename="/var/log/register.log",
            level=logging.INFO,
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )

        if sys.version_info >= (2, 7):
            logging.captureWarnings(True)

        return logging.getLogger(__name__)

    def print_and_log(self, msg, level):
        """
        Print and log a message
        """
        p_log = logging.getLogger(__name__)
        print(msg)

        if level == "info":
            printlogger = p_log.info
        elif level == "debug":
            printlogger = p_log.debug
        elif level == "warning":
            printlogger = p_log.warning
        elif level == "critical":
            printlogger = p_log.critical
        elif level == "error":
            printlogger = p_log.error
        elif level == "debug":
            printlogger = p_log.debug

        if level == "error":
            printlogger(msg, exc_info=True)
        else:
            printlogger(msg)

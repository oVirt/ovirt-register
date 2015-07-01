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
import glob
import os
import selinux
import subprocess
import logging

__LOGGER = logging.getLogger(__name__)


def execute_cmd(sys_cmd, env_shell=False):
    """
    Execute a command on the host

    sys_cmd -- Command to be executed
    shell   -- True or False  - executed through the shell environment
            (True is not recommended for security hazard)

    Return:
    output, error, returncode
    """
    try:
        cmd = subprocess.Popen(sys_cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=env_shell)
        output, err = cmd.communicate()
        if cmd.returncode != 0:
            raise OSError
    except OSError as e:
        __LOGGER.error("Cannot execute shell command", exc_info=True)
        raise e

    return output, err, cmd.returncode


def silent_restorecon(path):
    """Execute selinux restorecon cmd to determined file
    Args
    path -- full path to file
    """

    try:
        if selinux.is_selinux_enabled():
            selinux.restorecon(path)
    except:
        __LOGGER.error("restorecon {p} failed".format(p=path), "error")


class NodeImage(object):
    """
    REQUIRED: oVirt Node until 3.6

    To save the change across reboot, oVirt Node requires
    to call the persist API.

    To remove a file, it's required to do unpersist first
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def persist(self, fname=None):
        try:
            if self.check() and fname is not None:
                from ovirt.node.utils.fs import Config
                Config().persist(fname)
        except Exception as e:
            self.logger.exception("Exception: {exp}".format(exp=e))
            raise RuntimeError("Cannot persist {f}:\n {exc}".format(
                               f=fname,
                               exc=e))

    def check(self):
        """
        Check if the OS running is a node image

        Returns:
        True or False
        """
        return (os.path.exists('/etc/rhev-hypervisor-release') or
                bool(glob.glob('/etc/ovirt-node-*-release')))

    def unpersist(self, fname):
        try:
            if self.check() and fname is not None:
                from ovirt.node.utils.fs import Config
                Config().unpersist(fname)
        except Exception as e:
            self.logger.exception("Exception: {exp}".format(exp=e))
            raise RuntimeError("Cannot unpersist {f}:\n {exc}".format(
                               f=fname,
                               exc=e))

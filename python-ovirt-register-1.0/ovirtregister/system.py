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
import platform
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


def node_image():
    """
    Check if the OS running is a node image

    Returns:
    True or False
    """
    return (os.path.exists('/etc/rhev-hypervisor-release') or
            bool(glob.glob('/etc/ovirt-node-*-release')))


def _getAllMacs():
    """
    This functions has been originally written in VDSM project.
    Will be provided here to avoid the dependency project.
    REQUIRED_FOR: Engine 3.3
    """
    # (
    #     find /sys/class/net/*/device | while read f; do \
    #         cat "$(dirname "$f")/address"; \
    #     done; \
    #     [ -d /proc/net/bonding ] && \
    #         find /proc/net/bonding -type f -exec cat '{}' \; | \
    #         grep 'Permanent HW addr:' | \
    #         sed 's/.* //'
    # ) | sed -e '/00:00:00:00/d' -e '/^$/d'

    macs = []
    for b in glob.glob('/sys/class/net/*/device'):
        with open(os.path.join(os.path.dirname(b), "address")) as a:
            mac = a.readline().replace("\n", "")
        macs.append(mac)

    for b in glob.glob('/proc/net/bonding/*'):
        with open(b) as bond:
            for line in bond:
                if line.startswith("Permanent HW addr: "):
                    macs.append(line.split(": ")[1].replace("\n", ""))

    return set(macs) - set(["", "00:00:00:00:00:00"])


def persist(filename):
    """
    REQUIRED: oVirt Node until 3.6
    To save the change across reboot, oVirt Node requires
    to call the persist API.
    """
    if node_image():
        try:
            from ovirt.node.utils.fs import Config
            Config().persist(filename)
        except Exception as e:
            __LOGGER.exception("Exception: {exp}".format(exp=e))
            raise RuntimeError("Cannot persist: {f}:\n {exc}".format(
                               f=filename,
                               exc=e))


def getHostUUID(legacy=True):
    """
    This functions has been originally written in VDSM project.
    Will be provided here to avoid the dependency project.
    """
    __hostUUID = None
    __VDSM_ID = "/etc/vdsm/vdsm.id"

    try:
        if os.path.exists(__VDSM_ID):
            with open(__VDSM_ID) as f:
                __hostUUID = f.readline().replace("\n", "")
        else:
            arch = platform.machine()
            if arch in ('x86_64', 'i686'):
                out, err, ret = execute_cmd(["dmidecode", "-s",
                                            "system-uuid"])
                out = '\n'.join(line for line in out.splitlines()
                                if not line.startswith('#'))

                if ret == 0 and 'Not' not in out:
                    # Avoid error string - 'Not Settable' or 'Not Present'
                    __hostUUID = out.strip()
                else:
                    __LOGGER.warning('Could not find host UUID.')
            elif arch in ('ppc', 'ppc64'):
                # eg. output IBM,03061C14A
                try:
                    with open('/proc/device-tree/system-id') as f:
                        systemId = f.readline()
                        __hostUUID = systemId.rstrip('\0').replace(',', '')
                except IOError:
                    __LOGGER.warning('Could not find host UUID.')

            if legacy:
                try:
                    mac = sorted(_getAllMacs())[0]
                except:
                    mac = ""
                    __LOGGER.warning('Could not find host MAC.', exc_info=True)

                # __hostUUID might contain the string 'None' returned
                # from dmidecode call
                if __hostUUID and __hostUUID is not 'None':
                    __hostUUID += "_" + mac
                else:
                    __hostUUID = "_" + mac
    except:
        __LOGGER.error("Error retrieving host UUID", exc_info=True)

    if legacy and not __hostUUID:
        return 'None'
    return __hostUUID

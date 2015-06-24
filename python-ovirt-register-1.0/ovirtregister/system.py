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
import os
import uuid
import selinux
import subprocess
import logging
import platform

__EX_DMIDECODE = "/usr/sbin/dmidecode"
__LOGGER = logging.getLogger(__name__)


def node_image():
    """
    Check if the OS running is a node image

    Returns:
    True or False
    """
    node_img = False
    if os.path.exists("/etc/ovirt-node-iso-release") or \
            os.path.exists("/etc/rhev-hypervisor-release"):
        node_img = True

    return node_img


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


def host_uuid():
    """
    Collect UUID of host in /etc/vdsm/vdsm.id.
    In case it doesn't exist, it generated an UUID
    based on dmidecode plus one of MAC address of machine
    Format: UUID_MAC

    Return:
    UUID of host
    """
    __LOGGER.info("Processing UUID of host...")

    __uuid = None
    __vdsm_dir = "/etc/vdsm"
    __vdsm_id = "{v}/vdsm.id".format(v=__vdsm_dir)

    if os.path.exists(__vdsm_id):
        with open(__vdsm_id, 'r') as f:
            __uuid = f.read().strip("\n")
        return __uuid

    arch = platform.machine()
    generated_uuid = False
    if arch == 'x86_64':
        out, err, ret = execute_cmd([__EX_DMIDECODE, "-s", "system-uuid"])

        out = '\n'.join(line for line in out.splitlines()
                        if not line.startswith('#'))

        # Avoid error string- 'Not Settable' or 'Not Present'
        if ret == 0 and "Not" not in out:
            generated_uuid = out.replace("\n", "")
    elif arch == "ppc64":
        if os.path.exists('/proc/device-tree/system-id'):
            # eg. output IBM,03061C14A
            with open('/proc/device-tree/system-id') as f:
                generated_uuid = f.readline().rstrip('\0').replace(",", "")

    __mac_addr = ':'.join(
        ("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))

    __uuid = "{uuid}_{mac}".format(uuid=generated_uuid,
                                   mac=__mac_addr)

    # Save the generated uuid in vdsm.id
    if not os.path.exists(__vdsm_dir):
        os.makedirs(__vdsm_dir, 0o755)
        silent_restorecon(__vdsm_dir)

    with open(__vdsm_id, 'w+') as f:
        f.write(__uuid)

    if node_image():
        from ovirt.node.utils.fs import Config
        Config().persist(__vdsm_id)

    return __uuid


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

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
import glob
import platform
import logging

from . import system


class UUID(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def do_collect_host_uuid(self, force_uuid=None,
                             nopersist_uuid=None, reg_protocol=None):
        """
        Returns the host uuid

        Determine host UUID. If there is no existing /etc/vdsm/vdsm.id
        it will genereate UUID and save/persist in /etc/vdsm/vdsm.id

        Args:
        force_uuid   -- UUID that will be used for registration.
                        Useful for machine that duplicates uuid.

        nopersist_uuid -- Save the UUID into the disk (/etc/vdsm/vdsm.id)
                        (True or False)
        """
        _uuid = None
        __VDSM_DIR = "/etc/vdsm"
        __VDSM_ID = "{d}/vdsm.id".format(d=__VDSM_DIR)

        self.logger.debug("Processing UUID of host...")

        if os.path.exists(__VDSM_ID) and os.stat(__VDSM_ID).st_size == 0:
            system.NodeImage().unpersist(__VDSM_ID)
            os.unlink(__VDSM_ID)

        if not nopersist_uuid:
            if not os.path.exists(__VDSM_DIR):
                os.makedirs(__VDSM_DIR, 0o755)

        if reg_protocol == "legacy" and force_uuid is None:
            # REQUIRED_FOR: Engine 3.3
            # The legacy version uses the format: UUID_MACADDRESS
            _uuid = self._getHostUUID(legacy=True)

        elif reg_protocol == "service" and force_uuid is None:
            # Non legacy version uses the format: UUID
            _uuid = self._getHostUUID(legacy=False)

        if force_uuid is not None:
            _uuid = force_uuid

        if not nopersist_uuid and _uuid:
            with open(__VDSM_ID, 'w+') as f:
                f.write(_uuid)

            system.NodeImage().persist(__VDSM_ID)

        self.logger.debug("Host UUID: {u}".format(u=_uuid))

        return _uuid

    def _getAllMacs(self):
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

    def _getHostUUID(self, legacy=True):
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
                    out, err, ret = system.execute_cmd(["dmidecode", "-s",
                                                       "system-uuid"])

                    out = "{0}".format(out.decode('utf-8'))
                    out = '\n'.join(line for line in out.splitlines()
                                    if not line.startswith('#'))

                    if ret == 0 and 'Not' not in out:
                        # Avoid error string - 'Not Settable' or 'Not Present'
                        __hostUUID = out.strip()
                    else:
                        self.logger.warning('Could not find host UUID.')
                elif arch in ('ppc', 'ppc64'):
                    # eg. output IBM,03061C14A
                    try:
                        with open('/proc/device-tree/system-id') as f:
                            systemId = f.readline()
                            __hostUUID = systemId.rstrip('\0').replace(',', '')
                    except IOError:
                        self.logger.warning('Could not find host UUID.')

                if legacy:
                    try:
                        mac = sorted(self._getAllMacs())[0]
                    except:
                        mac = ""
                        self.logger.warning('Could not find host MAC.',
                                            exc_info=True)

                    # __hostUUID might contain the string 'None' returned
                    # from dmidecode call
                    if __hostUUID and __hostUUID is not 'None':
                        __hostUUID += "_" + mac
                    else:
                        __hostUUID = "_" + mac
        except:
            self.logger.error("Error retrieving host UUID", exc_info=True)

        if legacy and not __hostUUID:
            return 'None'
        return __hostUUID

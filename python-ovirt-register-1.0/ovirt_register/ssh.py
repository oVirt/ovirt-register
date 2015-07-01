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
import logging
import os
import pwd

from . import system
from .http import HTTP


class SSH(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def do_ssh_trust(self, ssh_user, ca_engine,
                     url_ssh_key, check_fqdn):
        """
        Download pub key and save it in the node
        """
        self.logger.debug("Collecting ssh pub key data...")
        _uid = pwd.getpwnam(ssh_user).pw_uid
        _auth_keys_dir = pwd.getpwuid(_uid).pw_dir + "/.ssh"
        _auth_keys = _auth_keys_dir + "/authorized_keys"
        self.logger.debug("auth_key is located {f}".format(f=_auth_keys))

        if not os.path.exists(_auth_keys_dir):
            os.makedirs(_auth_keys_dir, 0o700)
            system.silent_restorecon(_auth_keys_dir)
            system.NodeImage().persist(_auth_keys_dir)
            os.chown(_auth_keys_dir, _uid, _uid)

        res = HTTP().execute_request(url=url_ssh_key, check_fqdn=check_fqdn,
                                     ca_engine=ca_engine, cert_validation=True)

        http_res_str = res.decode("utf-8")

        # If authorized file exists, check if already exist
        # the entry
        if os.path.exists(_auth_keys):
            with open(_auth_keys, "r") as f_ro:
                if http_res_str.strip() in f_ro.read().strip():
                    return _auth_keys

        with open(_auth_keys, "a") as f_w:
            f_w.write(http_res_str)
            os.chmod(_auth_keys, 0o600)
            os.chown(_auth_keys, _uid, _uid)
            system.silent_restorecon(_auth_keys)
            system.NodeImage().persist(_auth_keys)

        return _auth_keys

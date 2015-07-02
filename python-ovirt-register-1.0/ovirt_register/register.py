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
import getpass
import socket
import sys
import logging

import requests

from . import system

from .uuid import UUID
from .pki import PKI
from .ssh import SSH
from .http import HTTP


class Register(object):

    def __init__(self, engine_fqdn, node_name=None,
                 ssh_user=None, ssh_port=None,
                 node_fqdn=None, fingerprint=None,
                 vdsm_port=None, check_fqdn=None,
                 ca_file=None, engine_https_port=None):

        """
        Attributes:
        node_name   - Name to Node
        engine_fqdn - Engine FQDN or address accessible from Node
        check_fqdn  - Validate Engine FQDN against CA (True or False)
        ssh_user    - SSH user that will establish the connection from Engine
        ssh_port    - The ssh port
        ca_file     - Store the CA file from oVirt Engine
        fingerprint - Validate the fingerprint provided against Engine CA
        node_fqdn   - Node FQDN or address accessible from Engine
        vdsm_port   - Communication port between node and engine, default 54321
        engine_https_port - Engine https port
        """

        try:
            # Disable unverified HTTPS requests warnings for pki download
            requests.packages.urllib3.disable_warnings()
        except Exception:
            if sys.version_info >= (2, 7, 0):
                logging.captureWarnings(True)

        self.logger = logging.getLogger(__name__)
        self.logger.debug("=======================================")
        self.logger.debug("ovirt-register has started")
        self.logger.debug("=======================================")
        self.logger.debug("Received the following attributes:")

        if node_name is None:
            self.node_name = socket.gethostname().split(".")[0]
        else:
            self.node_name = node_name
        self.logger.debug("Node name: {name}".format(name=self.node_name))

        self.check_fqdn = check_fqdn
        self.logger.debug("Check FQDN: {u}".format(u=check_fqdn))

        self.engine_fqdn = engine_fqdn
        self.logger.debug("Engine FQDN: {efqdn}".format(
                          efqdn=self.engine_fqdn))

        self.engine_url = "https://{e}".format(e=engine_fqdn)
        if engine_https_port is None:
            self.engine_port = "443"
        else:
            self.engine_port = engine_https_port
            self.engine_url = "https://{e}:{p}".format(e=self.engine_fqdn,
                                                       p=self.engine_port)

        self.logger.debug("Engine URL: {url}".format(url=self.engine_url))
        self.logger.debug("Engine https port: {hp}".format(
                          hp=self.engine_port))

        self.ca_engine = ca_file
        if self.ca_engine:
            self.logger.debug("CA File: {cf}".format(cf=self.ca_engine))

        if ssh_user is None:
            self.ssh_user = getpass.getuser()
        else:
            self.ssh_user = ssh_user
        self.logger.debug("SSH User: {user}".format(user=self.ssh_user))

        self.fprint = fingerprint
        self.logger.debug("Fingerprint: {fp}".format(fp=self.fprint))

        self.node_image = False
        if system.NodeImage().check():
            self.node_image = True
        self.logger.debug("Node image: {ni}".format(ni=self.node_image))

        if ssh_port is None:
            self.ssh_port = '22'
        else:
            self.ssh_port = ssh_port
        self.logger.debug("SSH Port: {sport}".format(sport=self.ssh_port))

        self.reg_protocol = None

        if vdsm_port is None:
            self.vdsm_port = '54321'
        else:
            self.vdsm_port = vdsm_port
        self.logger.debug("VDSM Port: {vport}".format(vport=self.vdsm_port))

        if node_fqdn is None:
            self.node_fqdn = socket.gethostname()
        else:
            self.node_fqdn = node_fqdn
        self.logger.debug("Node FQDN: {nfqdn}".format(nfqdn=self.node_fqdn))

        self.url_CA = None
        self.url_reg = None
        self.url_ssh_key = None
        self.temp_ca = None

        self.pki = PKI()

        self.logger.debug("=======================================")

    def pki_trust(self):
        """
        Executes the PKI trust
        """
        self.ca_engine, self.temp_ca_file = self.pki.do_pki_trust(
            url_CA=self.url_CA,
            ca_engine=self.ca_engine,
            user_fprint=self.fprint,
            reg_protocol=self.reg_protocol,
            check_fqdn=self.check_fqdn,
            engine_fqdn=self.engine_fqdn,
            engine_port=self.engine_port
        )

    def get_pem_fingerprint(self):
        """
        Returns the fingerprint of CA
        """
        return self.pki.do_get_pem_fingerprint()

    def get_pem_data(self):
        """
        Returns the fingerprint of CA
        """
        return self.pki.do_get_pem_data()

    def detect_reg_protocol(self):
        """
        Determine which registration protocol Engine
        is running: legacy or service
        REQUIRED_FOR: Engine 3.3
        """

        self.logger.debug("Identifying the registration protocol...")

        ucmd = "/ovirt-engine/services/host-register?version=1&command="
        __GET_VERSION = "https://{e}{u}{c}".format(e=self.engine_fqdn,
                                                   u=ucmd,
                                                   c="get-version")

        res = requests.get(__GET_VERSION, verify=False)
        if res.status_code != 200:
            self.reg_protocol = "legacy"
            self.url_CA = self.engine_url

            self.url_ssh_key = "{e}{k}".format(e=self.engine_url,
                                               k="/engine.ssh.key.txt")

            ureg = "/OvirtEngineWeb/register?vds_ip={fqdn}" \
                "&vds_name={name}&port={mp}".format(fqdn=self.node_fqdn,
                                                    name=self.node_name,
                                                    mp=self.vdsm_port)

            self.url_reg = "{e}{u}".format(e=self.engine_url, u=ureg)
        else:
            self.reg_protocol = "service"
            self.url_CA = "{e}{uc}{c}".format(e=self.engine_url,
                                              uc=ucmd,
                                              c="get-pki-trust")

            self.url_ssh_key = "{e}{uc}{c}".format(e=self.engine_url,
                                                   uc=ucmd, c="get-ssh-trust")

            ureg = "{uc}register&name={name}&address={fqdn}&sshUser={sshu}&" \
                   "sshPort={sshp}&port={mp}".format(uc=ucmd,
                                                     name=self.node_name,
                                                     fqdn=self.node_fqdn,
                                                     sshu=self.ssh_user,
                                                     sshp=self.ssh_port,
                                                     mp=self.vdsm_port)

            self.url_reg = "{e}{u}".format(e=self.engine_url, u=ureg)

        self.logger.debug("Registration procotol selected: {p}".format(
                          p=self.reg_protocol))

        self.logger.debug("Download CA via: {u}".format(u=self.url_CA))
        self.logger.debug("Download SSH via: {u}".format(u=self.url_ssh_key))

    def get_registration_protocol(self):
        """
        Return the current registration protocol

        None    - No protocol detected
        service - New protocol
        legacy  - The legacy protocol
        """
        return self.reg_protocol

    def ssh_trust(self):
        """
        Download pub key from Engine and save in ~/.ssh/authorized_keys
        """
        return SSH().do_ssh_trust(ssh_user=self.ssh_user,
                                  url_ssh_key=self.url_ssh_key,
                                  ca_engine=self.ca_engine,
                                  check_fqdn=self.check_fqdn)

    def collect_host_uuid(self, force_uuid, nopersist_uuid):
        """
        nopersist_uuid - If True, do not save the UUID in the disk
                         /etc/vdsm/vdsm.id

        force_uuid   - Force the UUID of machine. It's useful for machines
                       that provides duplicate UUID.
        """
        _uuid = UUID().do_collect_host_uuid(force_uuid=force_uuid,
                                            nopersist_uuid=nopersist_uuid,
                                            reg_protocol=self.reg_protocol)

        if self.reg_protocol == "legacy":
            self.url_reg += "&vds_unique_id={u}".format(u=_uuid)
        else:
            self.url_reg += "&uniqueId={u}".format(u=_uuid)

        self.logger.debug("Registration via: {u}".format(u=self.url_reg))

        return _uuid

    def execute_registration(self):
        """
        Trigger the registration command against Engine
        """
        self.logger.debug("Registration URL: %s" % self.url_reg)
        HTTP().execute_request(url=self.url_reg, check_fqdn=self.check_fqdn,
                               ca_engine=self.ca_engine, cert_validation=True)

        # Check if ca_engine is None (no provided) and temp file exists
        if self.temp_ca_file is not None and os.path.exists(self.ca_engine):
            os.unlink(self.ca_engine)

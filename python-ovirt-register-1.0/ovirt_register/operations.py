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
import hashlib
import logging
import os
import pwd
import shutil
import ssl
import sys
import requests
import tempfile

from . import system


class Operations(object):

    def __init__(self, engine_fqdn, fprint, check_fqdn,
                 ssh_user, ssh_port, node_fqdn, node_name,
                 vdsm_port, engine_url, engine_port):

        self.fprint = None
        self.ca_engine = None
        self.engine_url = engine_url
        self.engine_port = engine_port
        self.engine_fqdn = engine_fqdn
        self.check_fqdn = check_fqdn
        self.node_name = node_name
        self.node_fqdn = node_fqdn
        self.vdsm_port = vdsm_port
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.fprint = fprint

        try:
            # Disable unverified HTTPS requests warnings for pki download
            requests.packages.urllib3.disable_warnings()
        except Exception:
            if sys.version_info >= (2, 7, 0):
                logging.captureWarnings(True)

        self.logger = logging.getLogger(__name__)

    def host_uuid(self):
        """
        Determine host UUID and if there is no existing /etc/vdsm/vdsm.id
        it will genereate UUID and save/persist in /etc/vdsm/vdsm.id
        """
        _uuid = None
        __VDSM_ID = "/etc/vdsm/vdsm.id"

        self.logger.debug("Processing UUID of host...")

        if os.path.exists(__VDSM_ID) and os.stat(__VDSM_ID).st_size == 0:
            system.NodeImage().unpersist(__VDSM_ID)
            os.unlink(__VDSM_ID)

        if self.reg_protocol == "legacy":
            # REQUIRED_FOR: Engine 3.3
            # The legacy version uses the format: UUID_MACADDRESS
            _uuid = system.getHostUUID(legacy=True)
            self.url_reg += "&vds_unique_id={u}".format(u=_uuid)
        else:
            # Non legacy version uses the format: UUID
            _uuid = system.getHostUUID(legacy=False)
            self.url_reg += "&uniqueId={u}".format(u=_uuid)

        self.logger.debug("Registration via: {u}".format(u=self.url_reg))

        if not os.path.exists(__VDSM_ID) and _uuid:
            with open(__VDSM_ID, 'w') as f:
                f.write(_uuid)

            system.NodeImage().persist(__VDSM_ID)

        self.logger.debug("Host UUID: {u}".format(u=_uuid))

    def _execute_http_request(self, url, cert_validation=True):
        """
        Execute http requests
        url -- URL to be requested
        cert_validation -- SSL cert will be verified

        Returns: Content of http request
        """
        if self.check_fqdn:
            cert_validation = self.ca_engine
        else:
            cert_validation = False

        res = requests.get("{u}".format(u=url), verify=cert_validation)
        if res.status_code != 200:
            raise requests.RequestException(
                "http response was non OK, code {r}".format(r=res.status_code)
            )

        return res.content

    def get_protocol(self):
        """
        Determine if Engine is running in registration
        protocol version legacy or service
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

    def download_ca(self, ca_file):
        """
        Download CA from Engine and save in the filesystem if ca_file is
        specified
        """
        self.logger.debug("Collecting CA data from Engine...")

        temp_ca_file = False
        cert_exists = False

        self.ca_engine = ca_file

        if self.ca_engine is None:
            self.ca_dir = "/tmp"
            temp_ca_file = True
        else:
            self.ca_dir = os.path.dirname(self.ca_engine)

        if self.ca_engine and os.path.exists(self.ca_engine):
            calculated_fprint = self._calculate_fingerprint(self.ca_engine)
            cert_exists = True
        else:
            if not os.path.exists(self.ca_dir):
                os.makedirs(self.ca_dir, 0o755)
                system.silent_restorecon(self.ca_dir)
                system.NodeImage().persist(self.ca_dir)

            if self.reg_protocol == "legacy":
                # REQUIRED_FOR: Engine 3.3
                res = ssl.get_server_certificate(
                    (self.engine_fqdn, int(self.engine_port))
                )
            else:
                res = self._execute_http_request(self.url_CA,
                                                 cert_validation=False)

            with tempfile.NamedTemporaryFile(
                dir=self.ca_dir,
                delete=False
            ) as f:
                f.write(res)

            calculated_fprint = self._calculate_fingerprint(f.name)

        if self.fprint and self.fprint.lower() != calculated_fprint.lower():
            msg = "The fingeprints doesn't match:\n" \
                  "Calculated fingerprint: [{c}]\n" \
                  "Fingerprint provided:   [{a}]".format(c=calculated_fprint,
                                                         a=self.fprint)

            self.logger.error(msg)
            raise RuntimeError(msg)

        if not cert_exists and not temp_ca_file:
            shutil.move(f.name, self.ca_engine)
            system.NodeImage().persist(self.ca_engine)

        if temp_ca_file:
            os.unlink(f.name)

        self.fprint = calculated_fprint
        self.logger.debug("Calculated fingerprint: {f}".format(
                          f=self.fprint))

    def _calculate_fingerprint(self, cert):
        """Calculate fingerprint of certificate
        Args
        cert -- certificate file to be calculated the fingerprint

        Returns
        The fingerprint
        """
        with open(cert, 'r') as f:
            cert = f.read()
        print("Calculating Fingerprint...")
        fp = hashlib.sha1(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        fp = ':'.join(fp[pos:pos + 2] for pos in range(0, len(fp), 2))

        return fp

    def get_ca_fingerprint(self):
        """
        Returns the fingerprint of CA
        """
        return self.fprint

    def download_ssh(self, ssh_user):
        """
        Download ssh authorized keys and save it in the node
        """
        self.logger.debug("Collecting ssh pub key data...")
        _uid = pwd.getpwnam(self.ssh_user).pw_uid
        _auth_keys_dir = pwd.getpwuid(_uid).pw_dir + "/.ssh"
        _auth_keys = _auth_keys_dir + "/authorized_keys"
        self.logger.debug("auth_key is located {f}".format(f=_auth_keys))

        if not os.path.exists(_auth_keys_dir):
            os.makedirs(_auth_keys_dir, 0o700)
            system.silent_restorecon(_auth_keys_dir)
            system.NodeImage().persist(_auth_keys_dir)
            os.chown(_auth_keys_dir, _uid, _uid)

        res = self._execute_http_request(self.url_ssh_key)
        http_res_str = res.decode("utf-8")

        # If authorized file exists, check if already exist
        # the entry
        if os.path.exists(_auth_keys):
            with open(_auth_keys, "r") as f_ro:
                if http_res_str.strip() in f_ro.read().strip():
                    return

        with open(_auth_keys, "a") as f_w:
            f_w.write(http_res_str)
            os.chmod(_auth_keys, 0o600)
            os.chown(_auth_keys, _uid, _uid)
            system.silent_restorecon(_auth_keys,)
            system.NodeImage().persist(_auth_keys,)

    def execute_registration(self):
        """
        Trigger the registration command against Engine
        """
        self.logger.debug("Registration URL: %s" % self.url_reg)
        self._execute_http_request(self.url_reg)

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
import expts
import log
import logging
import M2Crypto
import os
import pwd
import system
import requests
import tempfile


class Operations(object):

    def __init__(self, engine_fqdn,
                 check_fqdn, logger):

        self.uuid = None
        self.fprint = None
        self.engine_fqdn = engine_fqdn
        self.check_fqdn = check_fqdn
        self.logger = logging.getLogger(__name__)
        self.print_and_log = log.Log().print_and_log

    def execute_http_cmd(self, exec_cmd, cert_validation=True):
        """ Execute registration commands in Engine

        exec_cmd -- Commands from Engine for Registration
        cert_validation -- SSL cert will be verified

        Possible exec_cmd:
            get-pki-trust -- Get pki trust
            get-ssh-trust -- Get ssh trust
            register      -- Execute registration (previous steps needed)

        Returns: Content of http request
        """
        url_cmd = "https://{engine}{url}".format(
            engine=self.engine_fqdn,
            url="/ovirt-engine/services/host-register?version=1&command="
        )
        self.logger.info("http cmd [%s]" % (url_cmd + exec_cmd))

        if cert_validation and self.check_fqdn:
            cert_validation = self.engine_ca
        else:
            cert_validation = False

        try:
            res = requests.get("{url}{cmd}".format(url=url_cmd, cmd=exec_cmd),
                               verify=cert_validation)

            if res.status_code != 200:
                self.logger.error("http response was not OK", exc_info=True)
                raise requests.RequestException
        except requests.RequestException as e:
            self.logger.error("Cannot connect to engine", exc_info=True)
            raise e

        return res.content

    def download_ca(self, fprint=None):
        """
        Download CA from Engine and save in /etc/pki/ovirt-engine/ca.pem

        Return: The fingerprint of cert
        """

        self.fprint = fprint
        self.ca_dir = "/etc/pki/ovirt-engine"
        self.engine_ca = "{dir}/ca.pem".format(dir=self.ca_dir)

        self.uuid = system.host_uuid()

        self.print_and_log("Collecting CA data from Engine...", level="info")
        if not os.path.exists(self.engine_ca):
            if not os.path.exists(self.ca_dir):
                os.makedirs(self.ca_dir, 0o755)
                system.silent_restorecon(self.ca_dir)
                if system.node_image():
                    from ovirt.node.utils.fs import Config
                    Config().persist(self.ca_dir)

            res = self.execute_http_cmd('get-pki-trust', cert_validation=False)

            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(self.ca_dir),
                delete=False
            ) as f:
                f.write(res)

            os.rename(f.name, self.engine_ca)

        calculated_fprint = self.__calculate_fingerprint(self.engine_ca)

        if self.fprint and self.fprint != calculated_fprint:
            msg = "The fingeprints doesn't match:\n" \
                  "Calculated fingerprint: [{c}]\n" \
                  "Attribute fingerprint:  [{a}]".format(c=calculated_fprint,
                                                         a=self.fprint)

            self.logger.error(msg, exc_info=True)
            raise expts.FingerprintError(msg)

        self.fprint = calculated_fprint
        self.logger.info("Calculated fingerprint: {f}".format(
                         f=calculated_fprint))

        if system.node_image():
            from ovirt.node.utils.fs import Config
            Config().persist(self.engine_ca)

    def __calculate_fingerprint(self, cert):
        """Calculate fingerprint of certificate
        Args
        cert -- certificate file to be calculated the fingerprint

        Returns
        The fingerprint
        """
        with open(cert, 'r') as f:
            cert = f.read()
        print("Calculating Fingerprint...")
        x509 = M2Crypto.X509.load_cert_string(cert, M2Crypto.X509.FORMAT_PEM)
        fp = x509.get_fingerprint('sha1')
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
        _auth_keys_dir = pwd.getpwuid(pwd.getpwnam(
                                      ssh_user).pw_uid).pw_dir + "/.ssh"
        _auth_keys = _auth_keys_dir + "/authorized_keys"

        if not os.path.exists(_auth_keys_dir):
            os.makedirs(_auth_keys_dir, 0o700)
            system.silent_restorecon(_auth_keys_dir)
            if system.node_image():
                from ovirt.node.utils.fs import Config
                Config().persist(_auth_keys_dir)

        res = self.execute_http_cmd('get-ssh-trust')
        with tempfile.NamedTemporaryFile(
            dir=_auth_keys_dir,
            delete=False
        ) as f:
            f.write(res)

        # If ssh key is new append it into autorized_keys
        with open(f.name, "r") as f_ro:
            content = f_ro.read()
            with open(_auth_keys, "a+") as f_w:
                if content not in f_w.read():
                    f_w.write(content)
                    os.chmod(_auth_keys, 0o600)
                    system.silent_restorecon(_auth_keys)

        os.unlink(f.name)

    def execute_registration(self, node_name,
                             node_fqdn, vds_port,
                             ssh_port, ssh_user):
        """
        Trigger the registration command against Engine
        """
        reg_cmd = "register" \
                  "&name={name}" \
                  "&address={addr}" \
                  "&uniqueId={uid}" \
                  "&vdsPort={vdsport}" \
                  "&sshUser={sshuser}" \
                  "&sshPort={sshport}".format(name=node_name,
                                              addr=node_fqdn,
                                              uid=self.uuid,
                                              vdsport=vds_port,
                                              sshuser=ssh_user,
                                              sshport=ssh_port)
        self.execute_http_cmd(reg_cmd)
        self.print_and_log("Registration completed, host is pending approval "
                           "on Engine: {e}".format(e=self.engine_fqdn),
                           level="info")

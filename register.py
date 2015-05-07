#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import getpass
import logging
import M2Crypto
import os
import uuid
import pwd
import selinux
import socket
import subprocess
import sys
import requests
import platform
import tempfile

_NODE_IMAGE = False
if os.path.exists("/etc/ovirt-node-iso-release") or \
        os.path.exists("/etc/rhev-hypervisor-release"):
    _NODE_IMAGE = True

_EX_DMIDECODE = "/usr/sbin/dmidecode"


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


class Register(object):

    def __init__(self, engine_fqdn, node_name=None,
                 ssh_user=None, ssh_port=None,
                 node_fqdn=None, fingerprint=None,
                 vds_port=None, check_fqdn=True):

        """
        The Register goal is to register any host againt Engine

        Attributes:
        node_name   - Name to Node
        engine_fqdn - Engine FQDN or address accessible from Node
        check_fqdn  - Validate Engine FQDN against CA (True or False)
        ssh_user    - SSH user that will establish the connection from Engine
        ssh_port    - The ssh port
        fingerprint - Validate the fingerprint provided against Engine CA
        node_fqdn   - Node FQDN or address accessible from Engine
        vds_port     - Communication port between node and engine, default 54321
        """

        self.logger = self.__logger()
        self.logger.info("=======================================")
        self.logger.info("Logging started")
        self.logger.info("=======================================")
        self.logger.info("Received the following attributes:")

        if node_name is None:
            self.node_name = socket.gethostname()
        else:
            self.node_name = node_name
        self.logger.info("Node name: {name}".format(name=self.node_name))

        self.check_fqdn = check_fqdn
        self.engine_fqdn = engine_fqdn
        self.logger.info("Engine FQDN: {efqdn}".format(efqdn=self.engine_fqdn))

        if ssh_user is None:
            self.ssh_user = getpass.getuser()
        else:
            self.ssh_user = ssh_user
        self.logger.info("SSH User: {user}".format(user=self.ssh_user))

        self.fprint = fingerprint
        self.logger.info("Fingerprint: {fp}".format(fp=self.fprint))

        self.node_image = False
        if _NODE_IMAGE:
            self.node_image = True
        self.logger.info("Node image: {ni}".format(ni=self.node_image))

        self.states_to_run = []

        if ssh_port is None:
            self.ssh_port = '22'
        else:
            self.ssh_port = ssh_port
        self.logger.info("SSH Port: {sport}".format(sport=self.ssh_port))

        if vds_port is None:
            self.vds_port = '54321'
        else:
            self.vds_port = vds_port
        self.logger.info("vds_port: {vport}".format(vport=self.vds_port))

        if node_fqdn is None:
            self.node_fqdn = socket.gethostname()
        else:
            self.node_fqdn = node_fqdn
        self.logger.info("Node FQDN: {nfqdn}".format(nfqdn=self.node_fqdn))

        self.url_cmd = "https://{engine}{url}".format(
            engine=self.engine_fqdn,
            url="/ovirt-engine/services/host-register?version=1&command="
        )
        self.logger.info("URL for Commands: {urlc}".format(urlc=self.url_cmd))

        self.ca_dir = "/etc/pki/ovirt-engine"
        self.engine_ca = "{dir}/ca.pem".format(dir=self.ca_dir)
        self.logger.info("CA dir: {ca}".format(ca=self.ca_dir))

        self.uuid = None
        self.logger.info("=======================================")

        """ Pre-defined states of object
            get_ca   - Download the CA pem
            get_ssh  - Get trust ssh
            register - Execute the registration
        """
        self.cmd = {
            'get_ca': self.__download_ca,
            'get_ssh': self.__download_ssh,
            'register': self.__execute_registration,
        }

    def __logger(self):
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

        return logging.getLogger(__file__)

    def __print_and_log(self, msg, level):
        """
        Print and log a message
        """
        print(msg)

        if level == "info":
            printlogger = self.logger.info
        elif level == "debug":
            printlogger = self.logger.info
        elif level == "warning":
            printlogger = self.logger.warning
        elif level == "critical":
            printlogger = self.logger.critical
        elif level == "error":
            printlogger = self.logger.error
        elif level == "debug":
            printlogger = self.logger.debug

        if level == "error":
            printlogger(msg, exc_info=True)
        else:
            printlogger(msg)

    def __execute_cmd(self, sys_cmd, env_shell=False):
        """
        Execute a command on the host

        sys_cmd -- Command to be executed
        shell   -- False
                   True or False  - executed through the shell environment
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
            self.logger.error("Cannot execute shell command",
                              exc_info=True)
            raise e

        return output, err, cmd.returncode

    def __host_uuid(self):
        """
        Collect UUID of host in /etc/vdsm/vdsm.id.
        In case it doesn't exist, it generated an UUID
        based on dmidecode plus one of MAC address of machine
        Format: UUID_MAC

        Return:
        UUID of host
        """
        self.__print_and_log("Processing UUID of host...", level="info")

        _vdsm_dir = "/etc/vdsm"
        _vdsm_id = "{v}/vdsm.id".format(v=_vdsm_dir)
        if os.path.exists(_vdsm_id):
            with open(_vdsm_id, 'r') as f:
                self.uuid = f.read().strip("\n")
            return self.uuid

        arch = platform.machine()
        generated_uuid = False
        if arch == 'x86_64':
            out, err, ret = self.__execute_cmd(
                [_EX_DMIDECODE, "-s", "system-uuid"])

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

        mac_addr = ':'.join(
            ("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))

        self.uuid = "{uuid}_{mac}".format(uuid=generated_uuid,
                                          mac=mac_addr)

        # Save the generated uuid in vdsm.id
        if not os.path.exists(_vdsm_dir):
            os.makedirs(_vdsm_dir, 0o755)
            self.__silent_restorecon(_vdsm_dir)

        with open(_vdsm_id, 'w+') as f:
            f.write(self.uuid)

        if self.node_image:
            from ovirt.node.utils.fs import Config
            Config().persist(_vdsm_id)

        return self.uuid

    def set_state(self, state):
        """
        Collect the states to run
        """
        self.states_to_run.append(state)

    def get_ca_fingerprint(self):
        """
        Returns the fingerprint of CA
        """
        return self.fprint

    def run(self):
        """
        Run states provided

        states - List of states to run
        """

        if not self.states_to_run:
            msg = "It's required to add a state before execute run!"
            self.logger.error(msg, exc_info=True)
            raise StatesError(msg)

        for state in self.states_to_run:
            try:
                if state not in self.cmd:
                    log = "The state [{s}] is invalid! " \
                          "Use the following states: ".format(s=state)

                    for key, val in list(self.cmd.items()):
                        log += "{k} ".format(k=key)
                    raise KeyError
            except KeyError as e:
                self.logger.error(log, exc_info=True)
                raise e
            self.logger.info("Executing state: {newstate}".format(
                             newstate=state))
            self.cmd[state]()

        self.states_to_run = []

    def __silent_restorecon(self, path):
        """Execute selinux restorecon cmd to determined file
        Args
        path -- full path to file
        """

        try:
            if selinux.is_selinux_enabled():
                selinux.restorecon(path)
        except:
            self.__print_and_log("restorecon {p} failed".format(p=path),
                                 "error")

    def __execute_http_cmd(self, exec_cmd, cert_validation=True):
        """ Execute registration commands in Engine

        exec_cmd -- Commands from Engine for Registration
        cert_validation -- SSL cert will be verified

        Possible exec_cmd:
            get-pki-trust -- Get pki trust
            get-ssh-trust -- Get ssh trust
            register      -- Execute registration (previous steps needed)

        Returns: Content of http request
        """
        self.logger.info("http cmd [%s]" % (self.url_cmd + exec_cmd))

        if cert_validation and self.check_fqdn:
            cert_validation = self.engine_ca
        else:
            cert_validation = False

        try:
            res = requests.get("{url}{cmd}".format(url=self.url_cmd,
                                                   cmd=exec_cmd),
                               verify=cert_validation)
            if res.status_code != 200:
                self.logger.error("http response was not OK", exc_info=True)
                raise requests.RequestException
        except requests.RequestException as e:
            self.logger.error("Cannot connect to engine", exc_info=True)
            raise e

        return res.content

    def __download_ca(self):
        """
        Download CA from Engine and save in /etc/pki/ovirt-engine/ca.pem

        Return: The fingerprint of cert
        """

        self.uuid = self.__host_uuid()
        self.__print_and_log("Collecting CA data from Engine...", level="info")

        if not os.path.exists(self.engine_ca):
            if not os.path.exists(self.ca_dir):
                os.makedirs(self.ca_dir, 0o755)
                self.__silent_restorecon(self.ca_dir)
                if self.node_image:
                    from ovirt.node.utils.fs import Config
                    Config().persist(self.ca_dir)

            res = self.__execute_http_cmd('get-pki-trust',
                                          cert_validation=False)
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
            raise FingerprintError(msg)

        self.fprint = calculated_fprint
        self.logger.info("Calculated fingerprint: {f}".format(
                         f=calculated_fprint))

        if self.node_image:
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

    def __download_ssh(self):
        """
        Download ssh authorized keys and save it in the node
        """
        _auth_keys_dir = pwd.getpwuid(pwd.getpwnam(
                                      self.ssh_user).pw_uid).pw_dir + "/.ssh"
        _auth_keys = _auth_keys_dir + "/authorized_keys"

        if not os.path.exists(_auth_keys_dir):
            os.makedirs(_auth_keys_dir, 0o700)
            self.__silent_restorecon(_auth_keys_dir)
            if self.node_image:
                from ovirt.node.utils.fs import Config
                Config().persist(_auth_keys_dir)

        res = self.__execute_http_cmd('get-ssh-trust')
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
                    self.__silent_restorecon(_auth_keys)

        os.unlink(f.name)

    def __execute_registration(self):
        """
        Trigger the registration command against Engine
        """
        reg_cmd = "register" \
                  "&name={name}" \
                  "&address={addr}" \
                  "&uniqueId={uid}" \
                  "&vdsPort={vdsport}" \
                  "&sshUser={sshuser}" \
                  "&sshPort={sshport}".format(name=self.node_name,
                                              addr=self.node_fqdn,
                                              uid=self.uuid,
                                              vdsport=self.vds_port,
                                              sshuser=self.ssh_user,
                                              sshport=self.ssh_port)
        self.__execute_http_cmd(reg_cmd)
        self.__print_and_log("Registration completed, host is pending "
                             "approval on Engine: [%s]" % self.engine_fqdn,
                             level="info")

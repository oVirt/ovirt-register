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
import getpass
import socket
import logging

from . import system
from . import operations


class Register(object):

    def __init__(self, engine_fqdn, node_name=None,
                 ssh_user=None, ssh_port=None,
                 node_fqdn=None, fingerprint=None,
                 vdsm_port=None, check_fqdn=True,
                 engine_https_port=None):

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
        vdsm_port   - Communication port between node and engine, default 54321
        engine_https_port - Engine https port
        """

        self.logger = logging.getLogger(__name__)
        self.logger.debug("=======================================")
        self.logger.debug("Logging started")
        self.logger.debug("=======================================")
        self.logger.debug("Received the following attributes:")

        if node_name is None:
            self.node_name = socket.gethostname().split(".")[0]
        else:
            self.node_name = node_name
        self.logger.debug("Node name: {name}".format(name=self.node_name))

        self.check_fqdn = check_fqdn
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

        if ssh_user is None:
            self.ssh_user = getpass.getuser()
        else:
            self.ssh_user = ssh_user
        self.logger.debug("SSH User: {user}".format(user=self.ssh_user))

        self.fprint = fingerprint
        self.logger.debug("Fingerprint: {fp}".format(fp=self.fprint))

        self.node_image = False
        if system.node_image():
            self.node_image = True
        self.logger.debug("Node image: {ni}".format(ni=self.node_image))

        self.states_to_run = []

        if ssh_port is None:
            self.ssh_port = '22'
        else:
            self.ssh_port = ssh_port
        self.logger.debug("SSH Port: {sport}".format(sport=self.ssh_port))

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

        self.logger.debug("=======================================")

        """ Pre-defined states of object
            get_ca   - Download the CA pem
            get_ssh  - Get trust ssh
            register - Execute the registration
            get_protocol - Check which registration protocol engine offers
            get_host_uuid - Get host uuid
        """

        self.op = operations.Operations(engine_fqdn=self.engine_fqdn,
                                        engine_url=self.engine_url,
                                        engine_port=self.engine_port,
                                        check_fqdn=self.check_fqdn,
                                        node_name=self.node_name,
                                        node_fqdn=self.node_fqdn,
                                        vdsm_port=self.vdsm_port,
                                        ssh_user=self.ssh_user,
                                        ssh_port=self.ssh_port,
                                        fprint=self.fprint)
        self.cmd = {
            'get_ca': self.__download_ca,
            'get_ssh': self.__download_ssh,
            'register': self.__execute_registration,
            'get_protocol': self.__get_protocol,
            'get_host_uuid': self.__get_host_uuid
        }

    def set_state(self, state):
        """
        Collect the states to run
        """
        self.states_to_run.append(state)

    def get_ca_fingerprint(self):
        """
        Returns the fingerprint of CA
        """
        return self.op.get_ca_fingerprint()

    def get_reg_protocol(self):
        """
        Returns the current protocol
        """
        return self.op.get_ca_fingerprint()

    def __get_host_uuid(self):
        """
        Returns the host uuid
        """
        return self.op.host_uuid()

    def __get_protocol(self):
        """
        Returns the current registration protocol in the Engine
        """
        return self.op.get_protocol()

    def __download_ca(self):
        """
        Get the PEM
        """
        return self.op.download_ca()

    def __execute_registration(self):
        """
        Registration step
        """
        return self.op.execute_registration()

    def __download_ssh(self):
        """
        Get the SSH authorize_key
        """
        return self.op.download_ssh(self.ssh_user)

    def run(self):
        """
        Run states provided

        states - List of states to run
        """

        if not self.states_to_run:
            msg = "It's required to add a state before execute run!"
            self.logger.exception(msg)
            raise RuntimeError("Exception {e}".format(e=msg))

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
            self.logger.debug("Executing state: {newstate}".format(
                              newstate=state))
            self.cmd[state]()

        self.states_to_run = []

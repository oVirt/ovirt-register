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
import getpass
import log
import socket
import operations
import system


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
        vds_port    - Communication port between node and engine, default 54321
        """

        self.logger = log.Log().start()
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
        if system.node_image():
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

        self.logger.info("=======================================")

        """ Pre-defined states of object
            get_ca   - Download the CA pem
            get_ssh  - Get trust ssh
            register - Execute the registration
        """

        self.op = operations.Operations(engine_fqdn=self.engine_fqdn,
                                        check_fqdn=self.check_fqdn,
                                        logger=self.logger)
        self.cmd = {
            'get_ca': self.__download_ca,
            'get_ssh': self.__download_ssh,
            'register': self.__execute_registration,
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

    def __download_ca(self):
        """
        Get the PEM
        """
        return self.op.download_ca(self.fprint)

    def __execute_registration(self):
        """
        Registration step
        """
        return self.op.execute_registration(node_name=self.node_name,
                                            node_fqdn=self.node_fqdn,
                                            vds_port=self.vds_port,
                                            ssh_user=self.ssh_user,
                                            ssh_port=self.ssh_port)

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
            self.logger.error(msg, exc_info=True)
            raise expts().StatesError(msg)

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

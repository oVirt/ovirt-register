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
import tempfile
import ssl
import shutil
import hashlib

import OpenSSL

from . import system
from .http import HTTP


class PKI(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pem_fingerprint = None
        self.pem_data = None

    def do_pki_trust(self, url_CA, ca_engine, check_fqdn,
                     user_fprint, reg_protocol, engine_fqdn,
                     engine_port):
        """
        Download CA from Engine and save in the filesystem if ca_file is
        specified
        """
        self.logger.debug("Collecting CA data from Engine...")

        temp_ca_file = None
        cert_exists = None

        if ca_engine is None:
            ca_dir = "/tmp"
            temp_ca_file = True
        else:
            ca_dir = os.path.dirname(ca_engine)

        if ca_engine and os.path.exists(ca_engine):
            self._pem_data(ca_engine)
            calculated_fprint = self._collect_fingerprint(ca_engine)
            cert_exists = True
        else:
            if not os.path.exists(ca_dir):
                os.makedirs(ca_dir, 0o755)
                system.silent_restorecon(ca_dir)
                system.NodeImage().persist(ca_dir)

            if reg_protocol == "legacy":
                # REQUIRED_FOR: Engine 3.3
                res = (
                    ssl.get_server_certificate(
                        (
                            engine_fqdn,
                            int(engine_port)
                        )
                    )
                )
            else:
                res = HTTP().execute_request(url=url_CA,
                                             ca_engine=ca_engine,
                                             cert_validation=False,
                                             check_fqdn=check_fqdn)

            with tempfile.NamedTemporaryFile(
                dir=ca_dir,
                delete=False
            ) as f:
                f.write(res)

            self._pem_data(f.name)
            calculated_fprint = self._collect_fingerprint(f.name)

        if user_fprint and user_fprint.lower() != calculated_fprint.lower():
            msg = "The fingeprints doesn't match:\n" \
                  "Calculated fingerprint: [{c}]\n" \
                  "Fingerprint provided:   [{a}]".format(c=calculated_fprint,
                                                         a=user_fprint)

            self.logger.error(msg)
            raise RuntimeError(msg)

        if not cert_exists and not temp_ca_file:
            shutil.move(f.name, ca_engine)
            system.NodeImage().persist(ca_engine)

        if temp_ca_file:
            ca_engine = f.name

        self.logger.debug("Calculated fingerprint: {f}".format(
                          f=self.pem_fingerprint))

        return ca_engine, temp_ca_file

    def _collect_fingerprint(self, cert):
        """
        collect fingerprint of certificate

        Args
        cert -- certificate file to be calculated the fingerprint

        Returns
        The fingerprint
        """
        with open(cert, 'r') as f:
            cert = f.read()
        fp = hashlib.sha1(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        self.pem_fingerprint = ':'.join(
            fp[pos:pos + 2] for pos in range(0, len(fp), 2)
        )

        return self.pem_fingerprint

    def do_get_pem_fingerprint(self):
        """
        Returns the fingerprint of CA
        """
        return self.pem_fingerprint

    def do_get_pem_data(self):
        """
        Returns the pem data
        """
        return self.pem_data

    def _pem_data(self, cert):
        """
        Collect PEM data

        cert -- pem path
        """
        pem_text = None

        if os.path.exists(cert):
            with open(cert, 'r') as f:
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    f.read()
                )

            pem_text = "Subject:"
            pem_text += "\n\tCountry Name: {0}\n".format(
                x509.get_subject().C
            )
            pem_text += "\tCommon Name: {0}\n".format(
                x509.get_subject().CN
            )
            pem_text += "\tOrganization Name: {0}".format(
                x509.get_subject().O
            )

            self.pem_data = pem_text
            self.logger.debug("PEM file data:")
            self.logger.debug("{0}".format(self.pem_data))

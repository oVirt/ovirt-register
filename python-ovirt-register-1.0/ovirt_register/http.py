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
import requests


class HTTP(object):
    def execute_request(self, url, check_fqdn,
                        ca_engine, cert_validation=True):
        """
        Execute http request
        url -- URL to be requested
        ca_engine -- The PEM file
        check_fqdn -- User input for checking FQDN
        cert_validation -- caller can specify if should check FQDN

        Returns: Content of http request
        """
        if not check_fqdn or not cert_validation:
            cert_validation = False
            ca_engine = None
        else:
            cert_validation = ca_engine

        try:
            res = requests.get("{u}".format(u=url), verify=cert_validation)
            if res.status_code != 200:
                raise requests.RequestException(
                    "http response was non OK, code {r}".format(
                        r=res.status_code
                    )
                )
        except Exception:
            if ca_engine and os.path.exists(ca_engine):
                os.unlink(ca_engine)
            raise

        return res.content

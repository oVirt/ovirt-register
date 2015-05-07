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
import argparse
import register


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='Tool to register node to Engine',
        epilog='Example of use:\n%(prog)s '
                    '--engine-fqdn engine.mydomain'
    )

    parser.add_argument(
        '--engine-fqdn',
        help="Engine FQDN (See also: --check-fqdn)",
        required=True
    )

    parser.add_argument(
        '--node-fqdn',
        help="Node FQDN or address",
    )

    parser.add_argument(
        '--node-name',
        help="Define a node name",
    )

    parser.add_argument(
        '--ssh-user',
        help="SSH username to establish the connection with Engine. "
             "If not provided, the user which is "
             "executing the script will catch and used",
    )

    parser.add_argument(
        '--ssh-port',
        help="SSH port to establish the connection with Engine "
             "If not provided, the script will use the default "
             "SSH port 22"
    )

    parser.add_argument(
        '--check-fqdn',
        help="Disable or Enable FQDN check for Engine CA, this option "
             "is enabled by default (Use: True or False)",
    )

    parser.add_argument(
        '--fingerprint',
        help="Specify an existing fingerprint to be validated against "
             "Engine CA fingerprint",
    )

    parser.add_argument(
        '--vds-port',
        help="The port to be used in the communication between the "
             "node agent and Engine, if not provided will be used "
             "the default port 54321"
    )
    args = parser.parse_args()

    reg = register.Register(engine_fqdn=args.engine_fqdn,
                            node_fqdn=args.node_fqdn,
                            node_name=args.node_name,
                            ssh_user=args.ssh_user,
                            ssh_port=args.ssh_port,
                            fingerprint=args.fingerprint,
                            vds_port=args.vds_port,
                            check_fqdn=args.check_fqdn)

    reg.set_state("get_ca")
    reg.run()

    yn = raw_input("Are you sure you want to accept the below "
                   "fingerprint from engine?\n"
                   "{f}\n(y/n) ".format(f=reg.get_ca_fingerprint()))

    print("User replied: [{r}]".format(r=yn))

    if "y" in yn.lower():
        reg.set_state("get_ssh")
        reg.set_state("register")
        reg.run()
    else:
        print("Okay aborting.. see you next time!")

#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import commands
import ipaddr
import os

def danted_setup(permitted_subnet_name, proxy_port=1080):
    """
    Configure and restart danted

    Raises an exception at the first fatal error.
    """

    if not permitted_subnet_name:
        permitted_subnet_name = '0.0.0.0/0'

    try:
        permitted_subnet = ipaddr.IPNetwork(permitted_subnet_name)
    except BaseException, exc:
        raise ValueError('Bad subnet expression [%s]: %s',
		permitted_subnet_name, str(exc))

    # danted only understands v4.
    #
    if not isinstance(permitted_subnet, ipaddr.IPv4Network):
        raise ValueError('Only IPv4 subnets are permitted [%s]',
                str(permitted_subnet))

    proxy_host = None
    my_ipaddr_names = commands.getoutput('hostname -I').split()
    for addr_name in my_ipaddr_names:
        addr = ipaddr.IPAddress(addr_name)

        if addr in permitted_subnet:
            proxy_host = addr_name
            break

    if not proxy_host:
	raise ValueError('ERROR: none of my networks appear to be permitted')

    # TODO: this print should be removed
    print 'Using proxy host address [%s]' % proxy_host

    danteconf = """
        internal: 127.0.0.1 port = %d
        external: %s
        method: username none #rfc931
        clientmethod: none
        user.notprivileged: nobody
        user.libwrap: nobody
        client pass {
                from: 0.0.0.0/0 port 1-65535 to: 0.0.0.0/0
        }
        client block {
                from: 0.0.0.0/0 to: 0.0.0.0/0
                log: connect error
        }
        pass {
             from: 0.0.0.0/0 to: 0.0.0.0/0
             protocol: tcp udp
        }""" % (proxy_port, proxy_host)

    os.system("/usr/bin/sudo /bin/echo '%s' > /etc/danted.conf" % danteconf)
    os.system('/usr/bin/sudo /etc/init.d/danted stop')
    os.system('/usr/bin/sudo /etc/init.d/danted start')


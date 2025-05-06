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

"""
Simple VPN client for use by Curveball
"""

import logging
import ipaddr
import os
import sys
import time

import cb.util.cblogging

from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
import twisted.internet.endpoints as endpoints

from cb.util.twistedtun import TwistedTUN
from cb.vpn.dns import DnsManagerLinux
from cb.vpn.dns import DnsManagerWindows
from cb.vpn.vpn_msg import VpnMsgWrapper
import cb.vpn.vpn_msg

import cb.util.platform

if cb.util.platform.PLATFORM == 'darwin':
    IP_PATH = '/sbin/route'
elif cb.util.platform.PLATFORM == 'android':
    IP_PATH = '/system/xbin/ip'
else:
    IP_PATH = '/sbin/ip'

class VpnClientState(object):
    """
    Namespace/scoping issues...
    """

    # The connection to the server.
    #
    # If None, then no connection currently exists.
    #
    SERVER = None

    # Ourselves
    #
    CLIENT = None

    # The TUN used for the VPN
    #
    # If None, then it hasn't been established yet.
    #
    TUN = None

    # The DNS state
    #
    DNS = None

    #
    NO_COVERT_DNS = False


class VpnClient(object):
    """
    Simple vpn-over-tcp-connection client.

    Note that this VPN does NOT provide any confidentiality,
    authenticity, or integrity guarantees.  These properties,
    if required, MUST be provided by the connection.  These
    properties are satisfied if the connection is a Curveball
    tunnel, for example.

    """

    class IncomingProtocol(Protocol):
        """
        Handler for messages from the server to the client
        """

        def __init__(self):
            self.log = logging.getLogger('cb.vpn_ct')
            self.recv_buffer = ''

        def connectionLost(self, reason):
            VpnClientState.SERVER = None

        def connectionMade(self):
            self.log.info("Initiating connection...")

            VpnClientState.SERVER = self

            # Now that we've got a complete connection to the server,
            # send it a message asking for it to respond with session
            # info that we need in order to set up the tun.
            #
            self.transport.write(VpnMsgWrapper.open_msg().pack())

        def dataReceived(self, data):

            # Is there a race condition with recv_buffer, or does twisted
            # make everything essentially single-threaded?

            # Parse whatever we get and act upon them.
            #
            (msgs, self.recv_buffer) = VpnMsgWrapper.recv_from_buffer(
                    self.recv_buffer + data)

            for msg in msgs:
                #print "Processing msg: " + str(msg) # debugging!

                if msg.get_msg_type() == cb.vpn.vpn_msg.FORWARD_PKT:
                    if VpnClientState.TUN:
                        VpnClientState.TUN.write(msg.get_msg_text())
                    else:
                        self.log.warn("dropping msg: NO TUN")

                elif msg.get_msg_type() == cb.vpn.vpn_msg.SESSION_INFO:
                    self.log.info("session info: %s" % (msg.get_msg_text(),))

                    if not VpnClientState.TUN:
                        (tun_ip, tun_netmask, dns_servers) = msg.parse_info()

                        VpnClientState.CLIENT.setup_tun(tun_ip, tun_netmask)

                        if VpnClientState.CLIENT._no_covert_dns:
                            self.log.info("Ignoring VPN-provided DNS info")
                        else:

                            # add covert host routes for the DNS servers
                            #
                            for addr in dns_servers:
                                self.log.info("Adding DNS (%s)" % (addr,))
                                VpnClientState.CLIENT.add_covert_hostroute(
                                        addr)

                            # reset the DNS to whatever parameters are provided.
                            #
                            VpnClientState.DNS.clear_servers()
                            VpnClientState.DNS.add_servers(dns_servers)

                        print "VPN ESTABLISHED"
                        self.log.info("VPN established")
                    else:
                        self.log.warn("VPN already configured?")

            return


    def __init__(self, vpn_addr, set_default=False, covert_subnets=[],
            no_covert_dns=False):
        """

        vpn_addr: an (ipaddr, port) tuple containing the
            address of the VPN service (relative to the
            SOCKS server, if SOCKS is used, or relative
            to the localhost).

        set_default: whether the default route should
            be set to the VPN.

        covert_subnets: a list of strings of the form
            ipaddr/maskwidth that specify the subnets
            that should be routed through the VPN.

        no_covert_dns: if true, then ignore the VPN-provided
            DNS server and use the pre-VPN'd DNS server.

        """

        self.log = logging.getLogger('cb.vpn_ct')

        (self._vpn_ipaddr, self._vpn_port) = vpn_addr
        if not self._vpn_ipaddr:
            self._vpn_ipaddr = '127.0.0.1'

        msg = 'using vpn addr %s:%d' % (
                self._vpn_ipaddr, self._vpn_port)
        print msg
        self.log.info(msg)

        self.dstFactory = Factory()
        self.dstFactory.protocol = VpnClient.IncomingProtocol

        self.connectDst()

        # explicit subnets to route through the VPN.
        #
        self._covert_subnets = covert_subnets

        # whether or not to use the VPN for DNS
        #
        self._no_covert_dns = no_covert_dns

        # whether to set the default route through the VPN.
        #
        self._set_default = set_default

        VpnClientState.CLIENT = self

        # Create DNS manager.
        #
	if sys.platform == 'win32':
	    VpnClientState.DNS = DnsManagerWindows()
	else:
	    VpnClientState.DNS = DnsManagerLinux()

        # To be set up when we configure the TUN
        #
        self.tun_ip = None
        self.tun_netmask = None


    def setup_tun(self, tun_ip, tun_netmask):
        """
        Set up the tun and the routes that use the tun
        """

        self.tun_ip = tun_ip
        self.tun_netmask = tun_netmask

        self.log.info('tun setup: ip %s netmask %s' %
                (str(self.tun_ip), str(self.tun_netmask)))

        tun = TwistedTUN(self.send_callback, '',
                ip_addr=self.tun_ip, netmask=self.tun_netmask,
                logname='cb.vpn_ct')

        self.set_routes()

        VpnClientState.TUN = tun


    def connectDst(self):
        """
        Create connection to the VPN server.
        """

        print "Connecting VPN"
        print "ipaddr %s port %s" % (self._vpn_ipaddr, self._vpn_port)

        endpoint = endpoints.TCP4ClientEndpoint(reactor,
                self._vpn_ipaddr, self._vpn_port, timeout=1)

        connection = endpoint.connect(self.dstFactory)
        connection.addErrback(self.dstConnectionFailed)

    def dstConnectionFailed(self, reason):
        """
        If we couldn't connect, try again in a bit
        """

        msg = "VPN connection failed, retrying..."
        print msg
        self.log.info(msg)

        reactor.callLater(5, self.connectDst)       
    

    def send_callback(self, rawpkt):

        self.log.debug("sending pkt (length %d)" % (len(rawpkt),))

        msg = VpnMsgWrapper.pkt_msg(rawpkt)

        if VpnClientState.SERVER:
            try:
                VpnClientState.SERVER.transport.write(msg.pack())

            except BaseException as err:
                # TODO: if sock is lost, then we need to somehow know
                # that it's time to pull everything down.  How to do this?
                # A callback from a callback?
                #
                self.log.warn("failed to send pkt (%s)" % (str(err),))
        else:
            self.log.warn("cannot send pkt; not connected")

        return

    def _del_vpn_route(self, subnet):
        # FIXME: don't use os.system
        if cb.util.platform.PLATFORM == 'darwin':
            route_cmd = '%s delete %s' % (IP_PATH, subnet)
        else:
            route_cmd = '%s route delete %s' % (IP_PATH, subnet)

        # FIXME: don't use os.system
        # print "subnet route:  " + route_cmd
        os.system(route_cmd)

    def _add_vpn_route(self, subnet):
        if cb.util.platform.PLATFORM == 'darwin':
            route_cmd = '%s add %s %s' % (IP_PATH, subnet, self.tun_ip)
        else:
            route_cmd = '%s route add %s via %s' % (IP_PATH,
                    subnet, self.tun_ip)

        # print "subnet route:  " + route_cmd
        # FIXME: don't use os.system
        os.system(route_cmd)

    def add_covert_hostroute(self, addr):
        self._del_vpn_route(addr + '/32')
        self._add_vpn_route(addr + '/32')

    def set_routes(self):
        """
        Set the covert routes to use the VPN.
        """

        # Set the route(s)
        #
        # NOTE: we make no effort to check that the set of routes
        # is sensible and consistent.  This should be done elsewhere.
        # This routine just plugs them in, ignoring any errors that
        # might occur.
        #
        # FIXME: we don't even log errors.  lame.
        #
        for subnet in self._covert_subnets:

            # Must drop routes before we can replace them.
            # This should be harmless if the routes are absent,
            # so just blindly pre-drop everything we want to add.

            self._del_vpn_route(subnet)
            self._add_vpn_route(subnet)

        # Note that we don't actually set the default route.  Instead
        # we set a pair of routes that span the entire address space,
        # and route through the tun.  This means that when the tun is
        # cleaned up, these two routes will automatically be removed,
        # and the default route never needs to be touched.
        #
        if self._set_default:
            self._del_vpn_route('0.0.0.0/1')
            self._del_vpn_route('128.0.0.0/1')

            self._add_vpn_route('0.0.0.0/1')
            self._add_vpn_route('128.0.0.0/1')

class WinVpnClient(VpnClient):
    """
    windows impl of the vpn client

    Most aspects are the same, but all the /sbin/ip commands
    need to be replaced with calls to netsh.
    """

    def __init__(self, vpn_addr, set_default=False, covert_subnets=[],
            no_covert_dns=False):
	super(WinVpnClient, self).__init__(vpn_addr, set_default,
		covert_subnets, no_covert_dns)

    def add_covert_hostroute(self, addr):

        # FIXME: don't use os.system
        route_cmd = 'route delete %s' % (addr,)
        os.system(route_cmd)

        route_cmd = 'route add %s MASK 255.255.255.255 %s' % (
		addr, self.tun_ip)
        # print "subnet route:  " + route_cmd
        # FIXME: don't use os.system
        os.system(route_cmd)


    def set_routes(self):
        """
        Set the covert routes to use the VPN.
        """

	# On windows, we need to make sure that the TUN device is "ready"
	# before we try to add routes through it; otherwise the routes will
	# be rejected.
	time.sleep(10)

        # Set the route(s)
        #
        # NOTE: we make no effort to check that the set of routes
        # is sensible and consistent.  This should be done elsewhere.
        # This routine just plugs them in, ignoring any errors that
        # might occur.
        #
        # FIXME: we don't even log errors.  lame.
        #
        for subnet in self._covert_subnets:
	    subnet_ip = ipaddr.IPv4Network(subnet)

	    subnet_prefix = str(subnet_ip.network)
	    subnet_mask = str(subnet_ip.netmask)

            # Must drop routes before we can replace them.
            # This should be harmless if the routes are absent,
            # so just blindly pre-drop everything we want to add.

            # FIXME: don't use os.system
            route_cmd = 'route delete %s' % (subnet_mask,)
            os.system(route_cmd)

            route_cmd = 'route add %s MASK %s %s' % (
                    subnet_prefix, subnet_mask, self.tun_ip)
            # print "subnet route:  " + route_cmd
            # FIXME: don't use os.system
            os.system(route_cmd)

        if self._set_default:
            # FIXME: don't use os.system
            # route_cmd = 'route delete 0.0.0.0'
            # os.system(route_cmd)

            route_cmd = 'route add 0.0.0.0 MASK 128.0.0.0 %s' % (
                    self.tun_ip,)
	    print 'route_cmd: [%s]' % (route_cmd,)
            os.system(route_cmd)

            route_cmd = 'route add 128.0.0.0 MASK 128.0.0.0 %s' % (
                    self.tun_ip,)
	    print 'route_cmd: [%s]' % (route_cmd,)
            os.system(route_cmd)
	    print 'default route set'



# TODO: must be run as root?
#
if __name__ == '__main__':

    def toy_main():
        # Assumed to run on 'vpn_client'

        try:
            covert_subnets = [
                        '8.8.8.0/24',      # Google DNS
                        '157.166.0.0/16',  # CNN sites
                        '128.89.80.126/32' # gremlin
                    ]

            _vpn = VpnClient(('10.0.0.11', 5555), True, [])

            reactor.run()
        finally:
            print "VPN LOST!"
            if VpnClientState.DNS:
                VpnClientState.DNS.restore_state()

    exit(toy_main())


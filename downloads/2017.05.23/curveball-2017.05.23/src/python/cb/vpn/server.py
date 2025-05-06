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
Implementation of a simple VPN server.
"""

import ipaddr
import logging
import os
import twisted.internet.endpoints as endpoints

import cb.util.cblogging

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol

from cb.util.free_src import FreeIPv4Addr
from cb.util.twistedtun import TwistedTUN
from cb.vpn.vpn_msg import VpnMsgWrapper
from cb.util.packet import Packet

class VpnServerState(object):
    """
    Container for global state that I really should pass around,
    but haven't figured out a graceful way to order the dependencies
    in twisted.  So, for now we use global variables.  Yuck.
    """

    # The tun device to which we foward/from which we receive packets
    #
    TUN = None

    # The dictionary of all of the client connections we have,
    # indexed by their VPN'd src IP.
    #
    CLIENTS = {}

    # local/private IP4Network owned by the VPN
    #
    TUN_SUBNET = None

    # Iterator for plucking address out of the TUN_SUBNET.
    #
    TUN_ADDR_POOL = None

    # FIXME: make into a parameter
    #
    DNS_SERVERS = ''


class VpnDpSrcProtocol(Protocol):
    """
    VPN source protocol: receive VPN messages from the clients
    and respond (typically by forwarding them through the TUN)
    """

    def __init__(self):
        self.log = logging.getLogger('cb.vpn_dp')

        self.log.debug('VpnDpSrcProtocol init')

        self._recv_buffer = ''
        self._opened_session = False
        self._client_ipaddr = None

    def dstAccept(self, _protocol):
        """
        accept method for new connections.

        (Is this method actually used?)
        """

        self.log.debug('VpnDpSrcProtocol dstAccept')

    def dataReceived(self, new_data):
        """
        Respond to data arriving from a client

        Parse the data into as many messages as possible (buffering
        any leftovers for later), and then process each message.
        """

        self.log.debug('dataReceived')

        self._recv_buffer += new_data

        try:
            (msgs, self._recv_buffer) = VpnMsgWrapper.recv_from_buffer(
                    self._recv_buffer)
        except BaseException, exc:
            # FIXME: recv_from_buffer can raise an exception.  If this happens,
            # we must drop the connection.
            #
            return

        for msg in msgs:
            msg_type = msg.get_msg_type()

            self.log.debug('dataReceived ' + str(msg))

            # TODO
            # should check that the msg makes sense, and the packet
            # we're about to forward isn't spoofed, forged, bogus...
            #
            if msg_type == cb.vpn.vpn_msg.FORWARD_PKT:

                msg_text = msg.get_msg_text()

                parsed_pkt = Packet(msg_text, read_only=True)
                src_ip = parsed_pkt.get_src()

                if src_ip != self._client_ipaddr:
                    self.log.warn('incorrect src for %d.%d.%d.%d' % (
                            ord(src_ip[0]), ord(src_ip[1]),
                            ord(src_ip[2]), ord(src_ip[3])))
                    # FIXME: bad packet == bad client; drop client
                else:
                    _written = VpnServerState.TUN.write(msg_text)

            elif msg_type == cb.vpn.vpn_msg.OPEN_SESSION:
                if self._opened_session:
                    self.log.warn('multiple OPEN_SESSION requests')
                    # FIXME: This client is bad, and should be dropped
                else:
                    self._opened_session = True

                    next_addr = VpnServerState.TUN_ADDR_POOL.alloc()

                    next_client_addr_str = str(next_addr)

                    # Smoosh the client ipaddr into binary, and then
                    # add the mapping from the binary ipaddr to ourselves for
                    # future error checking that src addrs are correct.
                    #
                    octets = next_client_addr_str.split('.')
                    ipaddr_binary = ''.join([chr(int(x)) for x in octets])

                    VpnServerState.CLIENTS[ipaddr_binary] = self
                    self._client_ipaddr = ipaddr_binary

                    self.log.info('assigning src_ip %s' %
                            (next_client_addr_str,))

                    info_msg = VpnMsgWrapper.info_msg(next_client_addr_str,
                            str(VpnServerState.TUN_NETWORK.netmask),
                            VpnServerState.DNS_SERVERS)

                    self.transport.write(info_msg.pack())

            elif msg_type == cb.vpn.vpn_msg.CLOSE_SESSION:
                self.log.info('CLOSE_SESSION request')
                # FIXME: actually close the session
            else:
                self.log.warn('unknown msg type (%d)' % (msg_type,))
                # FIXME: close the session.  (should have caught this already,
                # as an error from the recv, but if we get here something is out
                # of spec with the client; kill it)


class VpnServer(object):
    """
    Simple vpn server (eventually, just a skeleton right now)
    """

    def __init__(self, port, tun_subnet, outbound_dev, dns_servers):
        """
        Start a VPN server, listening on a given port.

        port: the local port on which to listen.

        tun_subnet: subnet that the tun is attached to.
            This should be a local, non-routed address.
            The server manages the assignment of address
            on this subnet.

        outbound_dev: the device used to route all of the packets
            that arrive via the TUN (i.e., 'eth1')

        dns_servers: comma-separated string of DNS servers to tell
            the client to use via the VPN
        """

        logname = 'cb.vpn_dp'

        self.log = logging.getLogger(logname)

        self.srcFactory = Factory()
        self.srcFactory.protocol = VpnDpSrcProtocol

        endpoint = endpoints.TCP4ServerEndpoint(reactor, port)

        self.tun_subnet = ipaddr.IPv4Network(tun_subnet)

        # Use the first addr in the subnet as the local tun_addr (the gateway
        # for all of the VPN connections) and then create a pool of addresses
        # for the clients to use, excluding this addr.
        #
        # NOTE: this depends on behavior of the ipaddr library.  It assumes that
        # self.tun_subnet[1] is going to be a usable address.
        #
        subnet_addr = str(self.tun_subnet[0])
        tun_addr = str(self.tun_subnet[1])

        omitted_addrs = [subnet_addr, tun_addr]

        self.log.warn('omitted addresses: (%s)' % str(omitted_addrs))

        addr_pool = FreeIPv4Addr(tun_subnet, 65536, omitted_addrs=omitted_addrs)

        self.tun = TwistedTUN(VpnServer.tun_callback, '',
                ip_addr=str(tun_addr), netmask=str(self.tun_subnet.netmask),
                logname=logname)

        # Route stuff to/from the tun.

        os.system('iptables -A INPUT -i %s -j ACCEPT' %
                (self.tun.iface_name(),))
        os.system('iptables -A FORWARD -i %s -j ACCEPT' %
                (self.tun.iface_name(),))

        # NAT everything from here.
        #
        os.system('iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE' %
                (tun_subnet, outbound_dev,))

        VpnServerState.TUN_NETWORK = self.tun_subnet
        VpnServerState.TUN_ADDR_POOL = addr_pool
        VpnServerState.DNS_SERVERS = dns_servers
        VpnServerState.TUN = self.tun

        endpoint.listen(self.srcFactory)

    @staticmethod
    def tun_callback(rawpkt):
        """
        Callback when pkts arrive from the TUN

        Figure out which client should receive the packet, and forward
        it along along that client connection.
        """

        msg = VpnMsgWrapper.pkt_msg(rawpkt)
        
        pkt = Packet(rawpkt, read_only=True)

        des_ip = pkt.get_dst()

        # Lookup the client to which this pkt should be sent.
        #
        try:
            point = VpnServerState.CLIENTS[des_ip]
            point.transport.write(msg.pack())
        except KeyError:
            logging.getLogger('cb.vpn_dp').debug('no client, dropping')
            print 'no client, dropping'


if __name__ == '__main__':
    def simple_main():
        """
        Simple driver that hardwires all of the parameters.
        """

        vpn_server_port = 5555
        vpn_subnet = '10.255.0.0/16'
        outbound_dev = 'eth1'
        dns_servers = '8.8.8.8,8.8.4.4'

        _vpnd = VpnServer(vpn_server_port, vpn_subnet,
                outbound_dev, dns_servers)

        reactor.run()

    exit(simple_main())

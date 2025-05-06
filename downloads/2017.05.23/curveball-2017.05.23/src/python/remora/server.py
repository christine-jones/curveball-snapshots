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

import netifaces
import sys

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor

from remora.protocol import RemoraMessage
from remora.protocol import RemoraMessageRequest
from remora.protocol import RemoraMessageResponse

from remora.dns_sniffer import RemoraDNSSniffer
from remora.sliver import RemoraDetectorSliver

class RemoraProtocol(Protocol):

    def __init__(self):

        self.msgtype_handler = {
            RemoraMessage.MSG_CURVEBALL_CONNECTION_REQUEST : self.req_handler,
        }

        self.recv_buffer = ''
        self.closed = True

        return

    def connectionMade(self):
        # print >> sys.stdout, ("remora client connected")
        self.closed = False

    def connectionLost(self, reason=None):
        # print >> sys.stdout, ("remora client disconnected")
        self.closed = True

    def dataReceived(self, data):

        self.recv_buffer += data

        while 1:
            (msg, self.recv_buffer) = RemoraMessage.recv_from_buffer(
                self.recv_buffer)

            if msg != None:
                self.handle_msg(msg)
            else:
                break

    def handle_msg(self, msg):

        if msg.msg_type in self.msgtype_handler:
            (self.msgtype_handler[msg.msg_type])(msg)

        else:
            print >> sys.stderr, ("RemoraProtocol:handle_msg: "
                "invalid message type %d" % msg.msg_type)

    def req_handler(self, msg):

        msg.__class__ = RemoraMessageRequest
        try:
            msg.unpack()
        except:
            print >> sys.stderr, ("RemoraProtocol:req_handler: invalid msg")
            return

        self.factory.remora.connection_request(self)

    def send_msg(self, msg):
        self.transport.write(msg.pack())

    def respond_to_client(self, decoy_addr, decoy_port, decoy_name):
        # print 'RESPONDING TO CLIENT: %s %d %s' % (
        #         decoy_addr, decoy_port, decoy_name)

        self.send_msg(RemoraMessageResponse(
                decoy_addr, decoy_port, decoy_name))


class RemoraServer(object):

    def __init__(self, server_addr, sniffer_interface):

        self.server_addr = server_addr
        self.sniffer_interface = sniffer_interface

        # determine mac address of interface
        self.sniffer_mac_addr = self.get_mac_addr(sniffer_interface)
        if self.sniffer_mac_addr == None:
            raise RuntimeError(
                    'cannot find MAC address of iface %s' % sniffer_interface)

        self.conn_requests = []

        # open server listening port
        self.server = Factory()
        self.server.protocol = RemoraProtocol
        self.server.remora = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor,
                server_addr[1], interface = server_addr[0])
        endpoint.listen(self.server)

        # start DNS packet sniffing and flow cluster detection
        #
        self.dns_sniffer = RemoraDNSSniffer(self, self.sniffer_interface,
                self.sniffer_mac_addr)

        # self.detector = RemoraDetectorCluster(
        #         self, self.sniffer_interface, self.sniffer_mac_addr)

        self.detector = RemoraDetectorSliver(self, self.sniffer_interface,
                self.sniffer_mac_addr, self.dns_sniffer.addr2host)

        self.addr2host = self.dns_sniffer.addr2host

    def get_mac_addr(self, iface):

        try:
            addrs = netifaces.ifaddresses(iface)
            mac = addrs[netifaces.AF_LINK][0]['addr']
        except IndexError:
            return None
        except KeyError:
            return None
        except BaseException:
            return None

        return mac

    def load_whitelist(self, filename):
        self.detector.load_whitelist(filename)

    def save_whitelist(self):
        self.detector.save_whitelist()

    def load_blacklist(self, filename):
        self.detector.load_blacklist(filename)

    def save_blacklist(self):
        self.detector.save_blacklist()

    def load_state(self, filename):
        self.detector.load_state(filename)

    def save_state(self):
        self.detector.save_state()

    def connection_request(self, protocol):
        self.conn_requests.append(protocol)

    def flow_cluster_detected(self, decoy_addr, decoy_port):

        if decoy_addr in self.dns_sniffer.addr2host:
            decoy_name = self.dns_sniffer.addr2host[decoy_addr][0]
        else:
            decoy_name = ''

        # It's possible that some clients closed their
        # connections before we gave them an answer.
        # Don't feed an answer to a dead connection; search
        # for one that still looks like it's alive
        #
        while len(self.conn_requests) > 0:
            protocol = self.conn_requests.pop(0)
            if not protocol.closed:
                # print 'Cluster start [response]: DECOY %s:%d' % (
                #         decoy_name, decoy_port)

                protocol.respond_to_client(decoy_addr, decoy_port, decoy_name)
                break

        print 'Cluster start [no client]: DECOY %s:%d' % (
                decoy_name, decoy_port)

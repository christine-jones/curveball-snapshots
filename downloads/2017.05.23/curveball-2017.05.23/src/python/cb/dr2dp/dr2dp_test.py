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

import socket
import threading
import time
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor

from cb.dr2dp.dr2dp import DR2DPMessage1
from cb.dr2dp.dr2dp import DR2DPMessageSentinelFilter
from cb.dr2dp.dr2dp import DR2DPMessageRedirectFlow
from cb.dr2dp.dr2dp import DR2DPMessageRemoveFlow
from cb.dr2dp.dr2dp import DR2DPMessageReassignFlow
from cb.dr2dp.dr2dp import DR2DPMessageTLSFlowEstablished
from cb.dr2dp.dr2dp import DR2DPMessageICMP


class TestProtocol(Protocol):

    def __init__(self):
        self.optype_handler = {
            DR2DPMessage1.OP_TYPE_PING : self.ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.forward_ip,
            DR2DPMessage1.OP_TYPE_SENTINEL_FILTER : self.sentinel_filter,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.redirect_flow,
            DR2DPMessage1.OP_TYPE_REMOVE_FLOW : self.remove_flow,
            DR2DPMessage1.OP_TYPE_REASSIGN_FLOW : self.reassign_flow,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.tls_flow,
            DR2DPMessage1.OP_TYPE_ICMP : self.icmp
        }

        self.recv_buffer = ''

    def connectionMade(self):
            self.factory.server.connected(self)

    def connectionLost(self, reason):
        pass

    def dataReceived(self, new_data):
        self.recv_buffer += new_data

        while 1:
            (msg, self.recv_buffer) = DR2DPMessage1.recv_from_buffer(
                                                        self.recv_buffer)

            if msg == None:
                break

            self.handle_msg(msg)

    def handle_msg(self, msg):
        if not msg.op_type in self.optype_handler:
            return False

        handler = self.optype_handler[msg.op_type]
        return handler(msg)

    def ping(self, msg):
        print 'PING message received:'
        print '  %s' % (str(msg),)

    def forward_ip(self, msg):
        print 'FORWARD_IP message received:'
        print '  %s' % (str(msg),)

    def sentinel_filter(self, msg):
        msg.__class__ = DR2DPMessageSentinelFilter
        msg.unpack()
        print 'SENTINEL_FILTER message received:'
        print '  %s' % (str(msg),)

    def redirect_flow(self, msg):
        msg.__class__ = DR2DPMessageRedirectFlow
        msg.unpack()
        print 'REDIRECT_FLOW message received:'
        print '  %s' % (str(msg),)

    def remove_flow(self, msg):
        msg.__class__ = DR2DPMessageRemoveFlow
        msg.unpack()
        print 'REMOVE_FLOW message received:'
        print '  %s' % (str(msg),)

    def reassign_flow(self, msg):
        msg.__class__ = DR2DPMessageReassignFlow
        msg.unpack()
        print 'REASSIGN_FLOW message received:'
        print '  %s' % (str(msg),)

    def tls_flow(self, msg):
        msg.__class__ = DR2DPMessageTLSFlowEstablished
        msg.unpack()
        print 'TLS_FLOW_ESTABLISHED message received:'
        print '  %s' % (str(msg),)

    def icmp(self, msg):
        msg.__class__ = DR2DPMessageICMP
        msg.unpack()
        print 'ICMP message received:'
        print ' %s' % (str(msg),)


class TestServer(object):

    def __init__(self, srcaddr):
        self.srcFactory = Factory()
        self.srcFactory.protocol = TestProtocol
        self.srcFactory.server = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor, srcaddr[1],
                                                interface=srcaddr[0])
        endpoint.listen(self.srcFactory)

    def connected(self, protocol):
        self.protocol = protocol


class TestDriver(threading.Thread):

    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock

    def run(self):

        print 'Sending PING message:'
        msg = DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                            DR2DPMessage1.OP_TYPE_PING)
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending FOWARD_IP message:'
        msg = DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                            DR2DPMessage1.OP_TYPE_FORWARD_IP,
                            '123456789abcdefghijklmnopqrstuvwxyz')
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending SENTINEL_FILTER messages:'
        msg = DR2DPMessageSentinelFilter(5)
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        msg = DR2DPMessageSentinelFilter(16, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending REDIRECT_FLOW messages:'
        msg = DR2DPMessageRedirectFlow(0, '', '', 'SentinelPacket')
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        msg = DR2DPMessageRedirectFlow(1, 'SYNOptions', 'ACKOptions',
                                       'SentinelPacket')
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending REMOVE_FLOW messages:'
        msg = DR2DPMessageRemoveFlow(socket.inet_aton('1.2.3.4'),
                                     socket.inet_aton('4.3.2.1'),
                                     1111, 2222, 5)
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending REASSIGN_FLOW messages:'
        msg = DR2DPMessageReassignFlow('1.2.3.4', '2.4.6.8', '3.5.7.9',
                                       1234, 5678, 3)
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending TLS_FLOW_ESTABLISHED messages:'
        msg = DR2DPMessageTLSFlowEstablished('1.2.3.4', '5.6.7.8',
                                             1234, 5678, 7,
                                             '0123456789012345678912345678')
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())

        print 'Sending ICMP messages:'
        msg = DR2DPMessageICMP('5.6.7.8', '1.2.3.4',
                               5678, 1234, 3, 1, 'ICMPPacket')
        print '  %s' % (str(msg),)
        self.sock.transport.write(msg.pack())


if __name__ == '__main__':

    def client_connected(protocol):
        print 'client connected'
        client_thread = TestDriver(protocol)
        client_thread.start()

    def test_main():
        server = TestServer(('', 4000))

        clientFactory = Factory()
        clientFactory.protocol = Protocol
        endpoint = endpoints.TCP4ClientEndpoint(reactor, '127.0.0.1', 4000)
        d = endpoint.connect(clientFactory)
        d.addCallback(client_connected)
        reactor.run()

    exit(test_main())

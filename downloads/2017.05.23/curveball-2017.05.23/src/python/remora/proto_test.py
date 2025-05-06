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

from remora.protocol import RemoraMessage
from remora.protocol import RemoraMessageRequest
from remora.protocol import RemoraMessageResponse

class TestProtocol(Protocol):

    def __init__(self):
        self.msgtype_handler = {
            RemoraMessage.MSG_CURVEBALL_CONNECTION_REQUEST  : self.req_handler,
            RemoraMessage.MSG_CURVEBALL_CONNECTION_RESPONSE : self.resp_handler
        }

        self.recv_buffer = ''

    def connectionMade(self):
        self.factory.server.connected(self)

    def connectionLost(self, reason):
        pass

    def dataReceived(self, new_data):
        self.recv_buffer += new_data

        while 1:
            (msg, self.recv_buffer) = RemoraMessage.recv_from_buffer(
                    self.recv_buffer)

            if msg == None:
                break

            self.handle_msg(msg)

    def handle_msg(self, msg):
        if not msg.msg_type in self.msgtype_handler:
            return False

        handler = self.msgtype_handler[msg.msg_type]
        return handler(msg)

    def req_handler(self, msg):
        msg.__class__ = RemoraMessageRequest
        msg.unpack()
        print 'request message received:'
        print '  %s' % str(msg)

    def resp_handler(self, msg):
        msg.__class__ = RemoraMessageResponse
        msg.unpack()
        print 'response message received:'
        print '  %s' % str(msg)


class TestServer(object):

    def __init__(self, srcaddr):
        self.srcFactory = Factory()
        self.srcFactory.protocol = TestProtocol
        self.srcFactory.server = self

        endpoint = endpoints.TCP4ServerEndpoint(
                reactor, srcaddr[1], interface=srcaddr[0])
        endpoint.listen(self.srcFactory)

    def connected(self, protocol):
        self.protocol = protocol


class TestDriver(threading.Thread):

    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock

    def run(self):

        print 'Sending request message:'
        msg = RemoraMessageRequest()
        print '  %s' % str(msg)
        self.sock.transport.write(msg.pack())

        print 'Sending empty response message:'
        msg = RemoraMessageResponse('0.0.0.0', 0)
        print ' %s' % str(msg)
        self.sock.transport.write(msg.pack())

        print 'Sending response message:'
        msg = RemoraMessageResponse('1.2.3.4', 1234, 'host', 'url')
        print '  %s' % str(msg)
        self.sock.transport.write(msg.pack())


if __name__ == '__main__':

    def client_connected(protocol):
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

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

import re
import socket
import sys

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor
from twisted.internet import error

from remora.protocol import RemoraMessage
from remora.protocol import RemoraMessageRequest
from remora.protocol import RemoraMessageResponse

class RemoraClientProtocol(Protocol):

    def __init__(self):

        self.msgtype_handler = {
            RemoraMessage.MSG_CURVEBALL_CONNECTION_RESPONSE : self.resp_handler,
        }

        self.recv_buffer = ''

    def connectionMade(self):
        print >> sys.stdout, ("connected to remora server")

        self.factory.remora.connected_to_server(self)

    def connectionLost(self, reason):
        print >> sys.stderr, ("connection to remora server closed")

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
            print >> sys.stderr, ("RemoraClientProtocol:handle_msg: "
                    "invalid message type %d" % msg.msg_type)

    def resp_handler(self, msg):

        msg.__class__ = RemoraMessageResponse
        try:
            msg.unpack()
        except:
            print >> sys.stderr, ("RemoraClientProtocol:resp_handler: "
                    "invalid message")
            return

        self.factory.remora.response_from_server()

    def send_msg(self, msg):
        self.transport.write(msg.pack())

    def send_remora_request(self):
        self.send_msg(RemoraMessageRequest())

    def close_connection(self):
        self.transport.loseConnection()


class RemoraClient(object):

    def __init__(self, addr, client_connected_callback=None):

        # check that the host name obeys RFC 1123
        label = '[a-zA-Z0-9-]*[a-zA-Z0-9]'
        if ((len(addr[0]) > 255) or
                (not re.match('^(%s\.)*(%s)$' % (label, label), addr[0]))):
            print >> sys.stderr, 'ERROR: bad hostname [%s]' % addr[0]
            return

        # input parameters
        self.addr = addr
        self.client_connected_callback = client_connected_callback

        # instance of client protocol, after successful connection
        self.client_protocol = None

        # callback to use when response received from remora server
        self.response_callback = None

        self.client = Factory()
        self.client.protocol = RemoraClientProtocol
        self.client.remora = self

        # connect to remora server
        endpoint = endpoints.TCP4ClientEndpoint(reactor, addr[0], addr[1])
        d = endpoint.connect(self.client)
        d.addErrback(self.connection_failed)

    def connection_failed(self, protocol):
        print >> sys.stderr, ("failed to connect to remora server")

    def send_remora_request(self, response_callback):

        # client must be connected in order to send request
        if self.client_protocol == None:
            return

        # callback to use when response is received
        self.response_callback = response_callback

        self.client_protocol.send_remora_request()

    def connected_to_server(self, protocol):
        self.client_protocol = protocol

        if self.client_connected_callback == None:
            return
        self.client_connected_callback()

    def response_from_server(self):

        # nobody to notify of response
        if self.response_callback == None:
            return

        self.response_callback()

        # reset callback for next request/response
        self.response_callback = None

    def close_connection(self):
        if self.client_protocol == None:
            return

        self.client_protocol.close_connection()


def remora_simple_request(remora_port):
    """
    Get parameters from the Remora server, and return them as
    (hostname, port), or return None if the Remora server is
    unavailable or returns an invalid answer.

    A simple, blocking Remora client interface suitable
    for applications, like curveball-client, that need to
    wait for the response and don't need asynchronous
    activity.
    """

    request = RemoraMessageRequest().pack()

    sock = socket.socket()
    sock.settimeout(3.0)

    try:
        sock.connect(('localhost', remora_port))
    except BaseException, exc:
        print 'Error: Remora connection failed: %s' % str(exc)
        return None

    sock.send(request)

    # Turn off the timeout; this might take a long time.
    #
    # The remora-server will let us know when it's got an answer
    # for us, and there's nothing we can do until then.
    #
    sock.settimeout(None)

    recv_buf = ''
    while 1:
        new_data = sock.recv(1024)

        # If the new_data is empty, that means that the Remora
        # server hung up for some reason; return None.
        if not new_data:
            return None

        recv_buf += new_data
        try:
            (msg, recv_buf) = RemoraMessage.recv_from_buffer(recv_buf)
        except BaseException, exc:
            print 'Error: Remora message badly formed: %s' % str(exc)
            return None

        if msg:
            break

    sock.close()

    if msg.msg_type == RemoraMessage.MSG_CURVEBALL_CONNECTION_RESPONSE:
        msg.__class__ = RemoraMessageResponse

        try:
            msg.unpack()
        except BaseException, exc:
            print 'Error: Remora message badly formed: %s' % str(exc)
            return None

        decoy_port = msg.port
        decoy_host = msg.host

        return (msg.host, msg.port)
    else:
        return None


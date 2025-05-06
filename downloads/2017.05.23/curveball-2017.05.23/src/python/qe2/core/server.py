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
The basic server objects

The ServerListener listens for new connections.  When a new
connection is accepted, it creates a ServerBottom for
that connection.

The first message on the ServerBottom connection must be a server
channel descriptor (OP_CHAN), which includes the information
necessary to instantiate a ServerChannel.  This includes the
channel uuid, the channel type, and any channel parameters
required for that type.  As soon as the OP_CHAN message is
received:

 - If a Server with the given UUID already exists,
    then link to that server.

 - Otherwise, create a Server instance for that uuid.

    The Server class is a subclass of Qe2Endpoint, and contains
    the reassembler for the inbound (client->server) data and
    the queue for the outbound (server->client) data.

    When we create a Server, also create a new ServerTop to go with it.
    The ServerTop communicates with the server app (typically a CCP
    server, but it could be anything)

 - Instantiate the appropriate ServerChannel, with a reference
    to the ServerBottom, based on the parameters in the OP_CHAN
    message

    At the current time, the ServerChannel parameters are
    limited

NOTE: although in theory it is possible for a single
connection to carry messages to more than one server (since
each message contains a UUID that names its endpoints) this
is forbidden by the protocol, so we don't need to mux between
connections and servers.  Each connection has exactly one
server.

"""

import uuid

import twisted.internet.endpoints as endpoints

from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet import reactor

from qe2.core.channel import Qe2SocketServerChannel
from qe2.core.endpoint import Qe2Endpoint
from qe2.core.log import QE2LOG
from qe2.core.msg import Qe2Msg
from qe2.core.params import Qe2Params

class Qe2ServerListener(object):
    """
    """

    def __init__(self, listen_addr, listen_port):
        """
        Create a listener for the given address and port.
        """

        # uuid2server maps the uuid to the server endpoint to use
        #
        self.uuid2server = dict()

        self.bottom_factory = Factory()
        self.bottom_factory.protocol = Qe2ServerBottom
        self.bottom_factory.server_listener = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor,
                listen_port, interface=listen_addr)
        endpoint.listen(self.bottom_factory)

class Qe2ServerBottom(Protocol):
    """
    The bottom half of the server protocol.

    data is received from the connection, and then passed to the endpoint.
    """

    INSTANCE_COUNTER = 1 # for debugging only

    def __init__(self):
        self.uuid = None
        self.server_top = None
        self.channel = None
        self.server = None

        self.recv_buf = '' # Could be a ByteArray
        self.msgs = list()

        self.marker = Qe2ServerBottom.INSTANCE_COUNTER
        Qe2ServerBottom.INSTANCE_COUNTER += 1

    def connectionMade(self):
        QE2LOG.info('Qe2ServerBottom.connectionMade()')

        self.factory.server_bottom = self

        # TODO: create a channel for the back traffic

    def dataReceived(self, data):

        QE2LOG.debug('dataReceived marker %d', self.marker)

        self.recv_buf += data

        (msgs, self.recv_buf) = Qe2Msg.recv(self.recv_buf)

        if not msgs:
            return

        # The first message on a channel MUST be an OP_CHAN message
        #
        # NOTE: in a full-featured channel, this message will describe the
        # channel and include parameters that the server should use,
        # but this is not implemented.  We always use the same channel
        # parameters.

        if not self.uuid:
            first_msg = msgs[0]

            if first_msg.opcode != Qe2Msg.OP_CHAN:
                QE2LOG.warn('channel started/resumed without OP_CHAN msg')
                self.loseConnection()

            msgs = msgs[1:]

            self.uuid = first_msg.uuid

            listener = self.factory.server_listener

            if not (self.uuid in listener.uuid2server):
                QE2LOG.info('Creating Qe2Server for uuid %s',
                        str(self.uuid).encode('hex'))
                listener.uuid2server[self.uuid] = Qe2Server(self.uuid)

            self.server = listener.uuid2server[self.uuid]

            # Register ourselves with our server endpoint
            #
            self.server.add_bottom(self)

            # We should get the parameters in the first OP_CHAN message
            #
            # TODO: this doesn't pay attention to the first message, but
            # instead makes assumptions about the parameters
            #
            if not self.channel:
                QE2LOG.debug('CREATING CHANNEL ON SERVER')
                self.channel = Qe2SocketServerChannel(
                        self.transport, self.server)

            # Immediately tell the client the UUID we selected for our
            # local UUID, so it can tell if we crash or the connections
            # are redirected.
            #
            # TODO: it would be better if this message didn't need to
            # happen immediately (because this gives the channel a
            # fingerprint) but instead was based on the channel parameters.
            #
            # Since we're ignoring the channel paramters in this version,
            # we don't have much choice, but a smarter channel would wait.
            #
            resp_msg = Qe2Msg(Qe2Msg.OP_INIT, self.uuid,
                    self.server.local_uuid, 0)
            self.transport.write(resp_msg.pack())

        endpoint = self.server

        endpoint.process_msgs(msgs)

    def connectionLost(self, reason=None):
        QE2LOG.info('Qe2ServerBottom.connectionLost()')

        # Deregister ourselves from our server endpoint, if we ever
        # registered ourselves.  (if this bottom never received any
        # messages, then it won't know it's uuid and therefore can't
        # register to its server)
        #
        if self.server:
            self.server.del_bottom(self)

        # If we have a looper polling for work, stop and delete it
        #
        if self.channel and self.channel.looper:
            self.channel.looper.stop()
            self.channel.looper = None

    def connectionFailed(self):
        QE2LOG.warn('Qe2ServerBottom.connectionFailed()')


class Qe2Server(Qe2Endpoint):
    """
    Implements the server side of the Qe2 protocol

    Created when a new quilt is detected.  It is an
    error for more than one Qe2Server to be associated
    with the same quilt uuid.
    """

    def __init__(self, quilt_uuid):
        """
        TODO: this app_port is fictious
        """

        # print 'Qe2Server.__init__()'

        # Error checking: make sure that local_port is sane

        super(Qe2Server, self).__init__()

        app_host = Qe2Params.get('SERVER_APP_HOST')
        app_port = Qe2Params.get('SERVER_APP_PORT')

        # self.uuid is the uuid created for this quilt by the client
        # for this quilt
        #
        self.uuid = quilt_uuid

        # self.local_uuid is used to answer back to OP_CHAN messages;
        # it identifies this endpoint uniquely, so if the quilt-server
        # crashes and reboots, or some similar disruption, the client
        # will know that the original endpoint has been lost
        #
        self.local_uuid = uuid.uuid4().bytes

        self.transport = None # Needs to be initialized later

        # We need to create a connection to the server app
        # which will serve as our local top

        self.top = None

        self.top_factory = Factory()
        self.top_factory.protocol = Qe2ServerTop
        self.top_factory.quilt_server = self

        QE2LOG.debug('Qe2ServerTop I AM CONNECTING TO (%s:%d)',
                str(app_host), app_port)

        endpoint = endpoints.TCP4ClientEndpoint(reactor,
                app_host, app_port, timeout=1)
        endpoint.connect(self.top_factory)

    def handle_init(self, msg):
        QE2LOG.error('server received an OP_INIT msg; unexpected')


class Qe2ServerTop(Protocol):
    """
    Manages the connection to the app.
    """

    def __init__(self):
        QE2LOG.debug('Qe2ServerTop.__init__()')

    def connectionMade(self):
        QE2LOG.debug('Qe2ServerTop.connectionMade()')

        self.factory.quilt_server.top = self
        self.app_connected = True

        server = None
        transport = None

        server = self.factory.quilt_server
        transport = self.transport

    def dataReceived(self, data):
        """
        Add the data to the pending queue
        """
        QE2LOG.debug('Qe2ServerTop.dataReceived(): %d bytes', len(data))

        self.factory.quilt_server.pending_out.enq(data)

    def connectionLost(self, reason=None):
        """
        server app has closed its connection with us.

        TODO: we should drop all connections for this server
        """

        QE2LOG.info('Qe2ServerTop.connectionLost(): YIKES!')
        self.app_connected = False

    def connectionFailed(self, reason=None):
        """
        Failed to connect to the app, or some other failure
        """

        QE2LOG.info('Qe2ServerTop.connectionFailed(): oops!')
        self.app_connected = False

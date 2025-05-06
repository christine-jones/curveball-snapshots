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
Simple quilt client class
"""

import uuid

import twisted.internet.endpoints as endpoints

from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet import reactor

from qe2.core.endpoint import Qe2Endpoint
from qe2.core.log import QE2LOG

class Qe2Client(Qe2Endpoint):
    """
    Implements the client side of the Qe2 protocol
    """

    def __init__(self, svr_host, svr_port, listen_host, listen_port):

        # Error checking: make sure that local_port is sane

        super(Qe2Client, self).__init__()

        self.uuid = uuid.uuid4().bytes

        self.svr_host = svr_host
        self.svr_port = svr_port

        # top_addr: the address we listen on for the app connection
        #
        self.top_addr = (listen_host, listen_port)

        # We don't have a top half yet.  We'll get one when we accept
        # the connection from the app
        #
        self.top = None

        self.top_factory = Factory()
        self.top_factory.protocol = Qe2ClientTop
        self.top_factory.endpoint = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor, listen_port,
                interface=listen_host)
        endpoint.listen(self.top_factory)

        # Create a connection factory that will create connections
        # to the server endpoint
        #
        # TODO: self.connection_factory = Qe2ConnectionFactory(uuid)

class Qe2ClientTop(Protocol):
    """
    Implements the top half of the client side of the Qe2 protocol.

    Listens for a client app connection, accepts, and then goes
    into the top half of the protocol: when data arrives from the
    client on the connection, enqueue it, and opportunistically
    forward it to the quilt server (via one or more tunnels).
    """

    def __init__(self):
        self.app_connected = False

    def connectionMade(self):
        """
        The app has connected.

        We only permit a single connection; if we have a connection,
        reject any others
        """

        if self.factory.endpoint.top:
            QE2LOG.warn('Qe2ClientTop.connectionMade: '
                    + 'rejecting second connection')
            self.transport.loseConnection()
        else:
            QE2LOG.info('Qe2ClientTop.connectionMade: '
                    + 'accepting first connection')
            self.factory.endpoint.top = self
            self.app_connected = True

    def dataReceived(self, data):
        """
        We have received data from the app; queue it to be sent to
        the channels.
        """

        QE2LOG.debug('Qe2ClientTop.dataReceived: %d bytes', len(data))

        self.factory.endpoint.pending_out.enq(data)

    def connectionLost(self, reason=None):
        """
        The app has closed its connection with us.

        We need to shut down, but we need to do it in a reasonable way.
        It might make sense to leave the channels open for a few moments,
        and pass some chaff through, or it might make sense to shut them
        down all together (i.e., if the browser exited, or the user
        closed a page in the browser)
        """

        QE2LOG.debug('Qe2ClientTop.connectionLost')
        QE2LOG.warn('SHUTTING DOWN QUILT')

        self.app_connected = False

        # Try to kill any lingering channels and their subprocesses
        #
        if self.factory.endpoint.chanman:
            self.factory.endpoint.chanman.stop_all()

    def connectionFailed(self, reason=None):
        """
        The app failed to connect, or something else happened.

        Check: can this even happen to an endpoint?
        """

        QE2LOG.warn('Qe2ClientTop.connectionFailed')
        self.app_connected = False

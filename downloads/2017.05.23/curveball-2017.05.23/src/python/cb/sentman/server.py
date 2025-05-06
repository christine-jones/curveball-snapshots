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
Implementation of the server side of the Sentman Protocol
"""

import logging
import os
import tempfile

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints

from twisted.internet import reactor

from cb.sentman.keystate import SentmanKey
from cb.sentman.keystate import SentmanKeyCollection
from cb.sentman.request import SentmanRequest
from cb.sentman.response import SentmanResponse

import cb.util.cblogging

DEFAULT_PORT = 1213

class SentmanServerProtocol(Protocol):
    """
    Implements a Sentman Server connection
    """

    def __init__(self):

        self.log = logging.getLogger('cb.sentman.server')
        self.log.debug('created new SentmanProtocol')
        self.pending_data = ''

    def connectionLost(self, reason=None):
        """
        Log that the connection has been lost.
        """

        self.log.debug('Closing connection')

    def connectionMade(self):
        """
        Note that a connection has been accepted.
        """

        self.log.debug('Accepting connection')

    def dataReceived(self, data):
        """
        """

        self.log.debug('dataReceived')

        self.pending_data += data
        zero_msg = chr(0) * SentmanResponse.SENTINEL_LEN

        try:
            (reqs, self.pending_data) = SentmanRequest.recv(self.pending_data)
        except BaseException, exc:
            self.log.warn('dataReceived: %s', str(exc))
            self.transport.loseConnection()
            return

        # check that there is exactly one message, with no leftovers

        if not reqs:
            err_str = 'no request found'
            self.log.warn(err_str)
            self.transport.loseConnection()

        if (len(reqs) > 1) or (len(self.pending_data) > 0):
            err_str = 'only one request is permitted'
            self.log.warn(err_str)
            self.transport.loseConnection()

        req = reqs[0]

        key_collection = self.factory.key_collection

        # If the caller is requesting a sentinel, then try to allocate one.
        # Otherwise, return the "zero" sentinel and the other metatdata.
        #
        sentinel = zero_msg
        code = SentmanResponse.STATUS_SUCCESS

        if req.op_type == SentmanRequest.ALLOCATE_SENTINEL:
            sentinel = self.factory.key_collection.generate()

            if not sentinel:
                code = SentmanResponse.STATUS_EXHAUSTED
                sentinel = zero_msg

        remaining = key_collection.remaining()
        epoch = key_collection.epoch()
        res = SentmanResponse(code, sentinel,
                remaining=remaining, epoch=epoch)

        self.transport.write(res.pack())


class SentmanServer(object):
    """
    Server side of Sentman
    """

    def __init__(self, port, key_collection):
        """
        Simple Sentman server (just a draft right now)
        """

        self.log = logging.getLogger('cb.sentman.server')

        # ensure that the port type/value are sane
        #
        if type(port) != int:
            err_str = 'port must be an int (not %s)' % type(port)
            self.log.warn(err_str)
            raise TypeError(err_str)

        # TODO: More checks of sanity: make sure that port is valid

        self.port = port

        # ensure that the key_collection is valid.
        # (it can be empty, but it can't be something bogus.  It has
        # to be an instance of SentmanKeyCollection)
        #
        if not isinstance(key_collection, SentmanKeyCollection):
            raise TypeError('key_collection must be a SentmanKeyCollection')

        self.factory = Factory()
        self.factory.protocol = SentmanServerProtocol

        self.factory.key_collection = key_collection

        endpoint = endpoints.TCP4ServerEndpoint(reactor,
                port, backlog=20, interface='127.0.0.1')
        endpoint.listen(self.factory)

if __name__ == '__main__':

    def test_main():
        """ a minimal server for testing purposes """

        key = SentmanKey(chr(3) * 256, sentinels_per_epoch=8)
        collection = SentmanKeyCollection('foo')
        collection.add_keystate(key)

        SentmanServer(1214, collection)
        reactor.run()

    exit(test_main())

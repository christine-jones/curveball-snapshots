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
Implementation of the client side of the Sentman Protocol

This is done in a very simple manner, and assumes that a synchronous
model is sufficient.
"""

import binascii
import logging
import socket

import cb.sentman.server
import cb.util.cblogging

from cb.sentman.request import SentmanRequest
from cb.sentman.response import SentmanResponse

class SentmanServerNotAvailable(BaseException):
    """
    Raised when the client cannot connect to the server
    """

    pass


class SentmanClient(object):
    """
    Implements a Sentman Client, which creates and drops
    connections as needed.
    """

    def __init__(self, port):
        """
        port - the local port of the sentman server.
        """

        if type(port) != int:
            raise TypeError('port must be an int')

        self.log = logging.getLogger('cb.sentman.client')
        self.log.debug('created new SentmanClient')

        self.port = port

    def allocate_sentinel(self, request_sentinel=True):
        """
        Create an allocation request, open a connection to the server,
        send the request, and wait for a response.  Return the response
        according to success or failure.
        """

        if request_sentinel:
            op_type = SentmanRequest.ALLOCATE_SENTINEL
        else:
            op_type = SentmanRequest.GET_INFO

        req = SentmanRequest(op_type)
        res = self.send_recv(req)

        return res

    def get_info(self):
        """
        A wrapper for allocate_sentinel: asks for info, but does not
        request a sentinel.
        """
        return self.allocate_sentinel(request_sentinel=False)

    def send_recv(self, request):
        """
        Do a synchronous connect/send/recv/disconnect for the given request.

        The request must be a proper SentmanRequest instance.
        """

        if not isinstance(request, SentmanRequest):
            raise TypeError('request must be a SentmanRequest')

        # If any of these fail, let the exception be caught by the caller.
        #
        sock = socket.socket()

        try:
            sock.connect(('127.0.0.1', self.port))
        except socket.error, exc:
            msg = '%d: %s' % (self.port, str(exc))
            raise SentmanServerNotAvailable(msg)

        request.send(sock)
        response_bytes = sock.recv(SentmanResponse.MESSAGE_LEN)

        if len(response_bytes) == 0:
            raise ValueError('socket closed before recv')

        if len(response_bytes) != SentmanResponse.MESSAGE_LEN:
            raise ValueError('short recv')

        (responses, remainder) = SentmanResponse.recv(response_bytes)

        if len(responses) < 1:
            raise ValueError('incomplete response received')

        if (len(responses) > 1) or (len(remainder) != 0):
            raise ValueError('too much data received')

        res = responses[0]
        self.log.info(str(res))

        return res

def get_sentinel(port=cb.sentman.server.DEFAULT_PORT):
    """
    Try to allocate a fresh sentinel.

    Returns a tuple (sentinel, msg) where sentinel is a fresh
    sentinel, or None if no sentinel can be allocated, and msg
    is a diagnostic (either 'Success' or some indication of
    why a sentinel could not be allocated.
    """

    cbsmd_client = SentmanClient(port)

    # Attempt to get the state info from of the cbmsd, but only
    # as a way to see whether there is a cbmsd running at all.
    # If this fails, it's probably because the cbmsd isn't running,
    # so try to start one.
    #
    try:
        cbsmd_client.get_info()
    except SentmanServerNotAvailable, _exc:

        # We could start a cbsmd here, but there are still issues
        # with getting all the right parameters here.
        #
        # print 'No cbmsd found.  Starting one...'
        # start_cbsmd(opts)

        return (None, 'No cbmsd found.  Please start one...')
    except BaseException, exc:
        return (None,
                'Unexpected failure to connect to cbmsd [%s]' % str(exc))

    try:
        res = cbsmd_client.allocate_sentinel()
    except BaseException, exc:
        return (None, 'Cannot connect to sentinel manager')

    status = res.get_status()
    if status == SentmanResponse.STATUS_EXHAUSTED:
        return (None, 'No sentinels available at this time')
    elif status != SentmanResponse.STATUS_SUCCESS:
        return (None, 'Sentinel allocation failed')
    else:
        return (binascii.hexlify(res.get_sentinel()), 'Success')


if __name__ == '__main__':
    import os
    import tempfile

    def test_main():
        """ basic request tests - requires a server to be running """

        client = SentmanClient(1214)

        print client.allocate_sentinel()
        print client.get_info()

        # TODO: check that the return values are sane.

    exit(test_main())

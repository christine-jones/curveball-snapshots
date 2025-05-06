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
SOCKS functionality for a TCP4ClientEndpoint

This is a bit of a gross hack, but is reasonably faithful to
the basic idea of twisted

What we do is have a shim Protocol that only knows how to do
the SOCKS handshake (and gets very upset if anything else happens),
and the real Protocol that we want to have connected, via SOCKS.

After the SOCKS handshake is complete, the shim instance
monkey-patches itself to become an instance of the desired type.

We only do SOCKS4 and SOCKS5 protocols, with no user-ID.
"""

import socket
import struct

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
import twisted.internet.endpoints as endpoints
import twisted.internet.protocol

from qe2.core.log import QE2LOG

class TCP4SocksClientEndpoint(object):
    """
    Wrapper for SocksShim, to make it look more like a
    TCP4ClientEndpoint.
    """

    def __init__(self, my_reactor, socks_host, socks_port, host, port,
            timeout=30, bindAddress=None):

        assert bindAddress == None, 'cannot honor bindAddress'

        self._reactor = my_reactor
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._host = host
        self._port = port
        self._timeout = timeout

        self._factory = None
        self._connection_attempts = 0
        self._max_connection_attempts = 20

    def connect(self, factory):
        """
        Instead of directly connecting, add the socks parameters
        to the given factory and use that factory to connect to the
        desired host:port, using do_connect().
        """

        factory.socks_dest_host = self._host
        factory.socks_dest_port = self._port
        factory.socks_dest_class = factory.protocol
        factory.protocol = SocksShim

        self._factory = factory

        self.do_connect()

    def do_connect(self):
        """
        Create a twisted TCP4ClientEndpoint and try to connect to
        the SOCKS server.

        This might not succeed at first, so set an errback to
        try again a few times before giving up.
        """

        endpoint = endpoints.TCP4ClientEndpoint(self._reactor,
                self._socks_host, self._socks_port, timeout=self._timeout)

        deferred = endpoint.connect(self._factory)
        deferred.addErrback(self.do_connect_failed)

    def do_connect_failed(self, reason):
        """
        If we haven't already tried to reconnect too many times,
        wait a brief moment and try again
        """

        if self._connection_attempts < self._max_connection_attempts:
            self._connection_attempts += 1
            QE2LOG.debug('TCP4SocksClientEndpoint.do_connect_failed: '
                    + 'trying again')
            self._reactor.callLater(0.5, self.do_connect)
        else:
            QE2LOG.warn('TCP4SocksClientEndpoint.do_connect_failed: giving up')


class SocksShim(Protocol):
    """
    A client-side Qe2Channel that connects to an ordinary socket 

    BEFORE the connection is requested, the factory must have
    the following member variables assigned set:

    socks_dest_host - the ipaddr or hostname of the destination

    socks_dest_port - the port of the destination

    socks_dest_class - the Protocol subclass to morph into after connected
    """

    HANDSHAKE_COMPLETE = 10
    HANDSHAKE_STATE_1 = 1
    HANDSHAKE_STATE_2 = 2

    def __init__(self):

        # We don't know the value of any of these yet: we won't know until
        # connectionMade occurs and we can tease them out of the factory
        # reference
        #
        self.socks_dest_ver = None
        self.socks_dest_host = None
        self.socks_dest_port = None
        self.socks_dest_class = None

        self.handshake_state = self.HANDSHAKE_STATE_1
        self.shim_recv_buf = ''

    def connectionMade(self):
        """
        After the connection is established, send the SOCKS4/SOCKS4a
        request to the server. 
        """

        # print '__SocksShim.connectionMade'

        self.socks_dest_host = self.factory.socks_dest_host
        self.socks_dest_port = self.factory.socks_dest_port
        self.socks_dest_class = self.factory.socks_dest_class

        # Decide whether to use SOCKS4 or SOCKS5 by testing
        # whether we have a dotted quad or something else.
        # If we already have a dotted quad address, then use
        # SOCKS4; otherwise use SOCKS5 with DNS resolution
        #
        try:
            _addr = socket.inet_aton(self.socks_dest_host)
        except socket.error:
            self.socks_dest_ver = 5
            self.handshake_socks5()
        except BaseException, exc:
            QE2LOG.error('SocksSum.connectionMade() [%s]', str(exc))
            self.transport.loseConnection()
        else:
            self.socks_dest_ver = 4
            self.handshake_socks4()

    def dataReceived(self, data):
        """
        Receive data in response to a handshake message, and dispatch
        to the correct handler (depending on which handshake we're
        doing

        If the handshake is complete, then monkey-patch this instance
        to have the desired class and initialize the new instance
        (with connectionMade() and dataReceived, if appropriate)
        """

        # print '__SocksShim.dataReceived'

        self.shim_recv_buf += data

        if self.socks_dest_ver == 4:
            self.data_recv_4()
        elif self.socks_dest_ver == 5:
            self.data_recv_5()
        else:
            QE2LOG.error('unhandled SOCKS version [%s]',
                    str(self.socks_dest_ver))
            assert(0)

        if self.handshake_state == self.HANDSHAKE_COMPLETE:
            # If we've reached this point, then everything is OK,
            # at least as far as we can tell at this point.
            #
            # Monkey-patch this instance, connect to the new class,
            # and then pretend to receive any pending data

            received = self.shim_recv_buf
            self.__class__ = self.socks_dest_class

            self.__init__()
            self.connectionMade()
            if received:
                self.dataReceived(received)

    def connectionLost(self,
            reason=twisted.internet.protocol.connectionDone):
        """
        Connection to the SOCKS server was lost during handshake
        """

        QE2LOG.error('SocksShim.connectionLost [%s] %s',
                str(self), str(reason))

    def connectionFailed(self, reason):
        """
        Could not connect to the SOCKS server
        """

        QE2LOG.warn('SocksShim.connectionFailed [%s] %s',
                str(self), str(reason))

    def handshake_socks4(self):
        """
        SOCKS4 handshake

        The danted SOCKS server doesn't seem to understand SOCKS4a,
        so this does not do the SOCKS4a trick of requesting DNS resolution
        on the proxy.

        The request has five fields:

        - The protocol number (4)
        
        - The request type (1 == TCP connection

        - The destination port (2 bytes, network order)

        - The destination ipaddr (4 bytes, network order)

        - The nul-terminated user-ID.  (1 byte, always 0)
        """

        # print 'SocksShim.handshake_socks4'

        request = struct.pack('!BBH', 4, 1, self.socks_dest_port)

        try:
            addr = socket.gethostbyname(self.socks_dest_host)
        except BaseException, exc:
            QE2LOG.error('SocksShim.handshake_socks4 ERROR [%s]', str(exc))
            self.transport.loseConnection()
            return

        request += socket.inet_aton(addr)
        request += '\x00'

        self.transport.write(request)

    def handshake_socks5(self):
        """
        SOCKS5 handshake

        We only support a subset of SOCKS5 -- TCP, no authentication,
        IPv4 addresses (if an address is given)

        The SOCKS5 handshake has two states: requesting a connection
        to the SOCKS server itself, and then requesting a connection
        via that server.  If handshake_state == 1, then this sends the
        first request; otherwise it sends the second.
        """

        # print 'SocksShim.handshake_socks5 %s' % str(self.handshake_state)

        # TODO: check that the socks_dest_host is a string, and short
        # enough to be sane.

        if self.handshake_state == self.HANDSHAKE_STATE_1:
            request = '\x05\x01\x00'
            self.transport.write(request)
        elif self.handshake_state == self.HANDSHAKE_STATE_2:
            # Even though this looks like the same request that
            # we send in state 1, the bytes have a different semantic
            # so I don't want to combine them.
            #
            request = '\x05\x01\x00'

            # Figure out whether the address is a dotted quad already,
            # or whether we need to ask for resolution.  If we try to
            # convert it directly to binary, and we get a socket.error,
            # then it's a DNS name.

            try:
                addr = socket.inet_aton(self.socks_dest_host)
            except socket.error:
                request += '\x03'
                request += chr(len(self.socks_dest_host))
                request += self.socks_dest_host
            except BaseException, exc:
                QE2LOG.warn('SocksShim.handshake_socks5 (2) ERR [%s]',
                        str(exc))
                self.transport.loseConnection()
                return
            else:
                request += '\x01'
                request += addr

            request += struct.pack('!H', self.socks_dest_port)

            self.transport.write(request)
        else:
            QE2LOG.error('SocksShim.handshake_socks5 unhandled state')

    def data_recv_4(self):
        """
        Handle the SOCKS4 response
        """

        needed = 8

        if len(self.shim_recv_buf) < needed:
            return

        response = self.shim_recv_buf[:needed]
        self.shim_recv_buf = self.shim_recv_buf[needed:]

        (_null, status, _port, _ipaddr) = struct.unpack('!BBHL', response)

        if status != 0x5a:
            QE2LOG.warn('SOCKS4 connection failed %x %x %x',
                    status, _ipaddr, _port)
            self.transport.loseConnection()
        else:
            self.handshake_state = self.HANDSHAKE_COMPLETE

        return

    def data_recv_5(self):
        """
        Handle the SOCKS responses
        """

        # QE2LOG.debug('incoming len %d', len(self.shim_recv_buf))

        if self.handshake_state == self.HANDSHAKE_STATE_1:
            if len(self.shim_recv_buf) < 2:
                return

            if self.shim_recv_buf[:2] != '\x05\x00':
                QE2LOG.warn('failed SOCKS5 first response')
                self.transport.loseConnection()
            else:
                self.shim_recv_buf = self.shim_recv_buf[2:]
                self.handshake_state = self.HANDSHAKE_STATE_2

                self.handshake_socks5()

        elif self.handshake_state == self.HANDSHAKE_STATE_2:

            # NOTE: we only handle the case where the server returns
            # us an ordinary IPv4 address (which is expected for a
            # TCP connect request).  If a server returns a DNS-type
            # address, which has a variable length, this function
            # can't parse it yet.

            resp_len = 10
            if len(self.shim_recv_buf) < resp_len:
                return

            response = self.shim_recv_buf[:resp_len]
            self.shim_recv_buf = self.shim_recv_buf[resp_len:]

            expected_prefix = '\x05\x00\x00\x01'

            if response[:len(expected_prefix)] != expected_prefix:
                QE2LOG.warn('failed SOCKS5 second response [prefix]')
                self.transport.loseConnection()
                return

            # NOTE: we do not attempt to validate the returned IPv4
            # address or ephemeral port.  We could check them for
            # basic sanity (make sure they're valid, at least) but
            # we can't check that they're *correct*.

            self.handshake_state = self.HANDSHAKE_COMPLETE

        else:
            QE2LOG.error('SocksShim.data_recv_5 unhandled state')
            assert(0)


if __name__ == '__main__':
    QE2LOG.setLevel(1)

    class UrlFetcher(Protocol):
        """
        A simple protocol to fetch / from a web server
        """

        def __init__(self):
            pass

        def connectionMade(self):
            """
            As soon as we have a connection, send
            a GET request.  Assumes that the web server
            isn't fussy about getting a Host: parameter
            """

            self.transport.write('GET / HTTP/1.1\r\n\r\n')

        def dataReceived(self, data):
            """
            Dump out the data to stdout
            """
            print '<data>%s</data>' % data

        def connectionLost(self,
                reason=twisted.internet.protocol.connectionDone):
            print 'UrlFetcher.connectionLost [%s] %s' % (
                    str(self), str(reason))

        def connectionFailed(self, reason):
            print 'UrlFetcher.connectionFailed [%s] %s' % (
                    str(self), str(reason))

    def test_shim(host_addr):
        """
        Assumes that there's a SOCKS server listening on
        localhost:1080, and that there's a web server
        listening on host_addr:80.
        """

        factory = Factory()
        factory.protocol = SocksShim
        factory.socks_dest_host = host_addr
        factory.socks_dest_port = 80
        factory.socks_dest_class = UrlFetcher

        endpoint = endpoints.TCP4ClientEndpoint(reactor, '', 1080, timeout=1)
        endpoint.connect(factory)

    def test_socks4(host_addr, host_port):

        factory = Factory()
        factory.protocol = UrlFetcher

        endpoint = TCP4SocksClientEndpoint(reactor,
                '', 1080, host_addr, host_port, timeout=1)
        endpoint.connect(factory)

    def test_main():
        """
        Just run the test_shim.  Requires eyeballing the output
        """

        # test_shim('decoy')
        # test_shim('10.0.20.11')
        test_socks4('www.cnn.com', 80)

        reactor.run()

    test_main()

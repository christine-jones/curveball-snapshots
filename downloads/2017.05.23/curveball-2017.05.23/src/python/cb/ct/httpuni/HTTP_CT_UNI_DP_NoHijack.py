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
Server end of the HTTP-unidirectional covert channel
"""

import re
import sys

from M2Crypto import RC4
from M2Crypto import RC4

import twisted.internet.endpoints as endpoints
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
from twisted.python import log

import cb.util.cblogging
import cb.util.cb_constants as const
import cb.util.http_util_req as http_util
from cb.mole.c_encode import HttpMoleCryptoEncoder


class DstProtocol(Protocol):
    """
    CT_DP <-> CCP_DP protocol
    """
    def __init__(self):
        self.cc = None
        self.recv_buf = ''

    def connectionMade(self):
        self.cc = self.factory.src_protocol

    def connectionLost(self, reason):
        """
        Connection lost to dst (CCP_DP), so close connection to client
        """
        self.cc.transport.loseConnection()

    def dataReceived(self, new_data):
        """
        Read data from CCP_DP to CCP_client, to be sent via CT.
        """
        self.recv_buf += new_data
        
        if self.cc.mole:
            self.cc.mole.enqueue( self.recv_buf )
            self.recv_buf = ""
        else:
            print "Could not enqueue mole data"

class SrcProtocol(Protocol):

    def __init__(self):

        global ccp_port

        self.mole = None
        self.dstFactory = None
        self.dst_protocol = None # DstProtocol instance
        self.buf = ''
        self.isFirst = True
        self.ct_dp = None
        self.rc4 = None
        self.session_key = None
        self.data_buf = ''
        self.curr_count = None

        # We don't use the host or session_key parameters because the
        # only thing we use this encoder for is its digest method, which
        # does not depend on anything except the text.
        #
        self.encoder = HttpMoleCryptoEncoder('fakehost', 'fakekey')

    def connectionMade(self):
        """
        We've connected to a src. Make a connection to the dst (CCP).
        """
        dstFactory = Factory()
        dstFactory.protocol = DstProtocol
        dstFactory.src_protocol = self

        endpoint = endpoints.TCP4ClientEndpoint(
                reactor, self.factory.dstaddr[0],self.factory.dstaddr[1])

        d = endpoint.connect( dstFactory )
        d.addCallback( self.dstConnected )

    def dataReceived(self, data):


        if self.isFirst == True:
            self.mole = self.factory.ct_dp.getMole()
            self.session_key = self.mole.get_session_key()
            self.rc4 = RC4.RC4(self.session_key[const.SENTINEL_HEX_LEN:])
            self.isFirst = False

        self.data_buf += data

        while len(self.data_buf) > 0:
            (status, self.data_buf) = self.tunnelIsReady(self.data_buf)
            if not status:
                break

    def connectionLost(self, reason):
        """
        We've lost the connection to the src (client), shut down
        the connection to the dst (CCP_DP).
        """
        print "HTTP CT_DP UNI connectionLost"

        if not self.dst_protocol is None:
            self.dst_protocol.transport.loseConnection()

        if not self.factory.ct_dp is None:
            self.factory.ct_dp.tunnelLost(self, self.dst_protocol)

        p = self.transport.getPeer()
        self.factory.cm_close_callback((p.host, p.port))

    def dstConnected(self, protocol):

        self.dst_protocol = protocol
        if self.ct_dp:
            self.ct_dp.tunnelMade( self, self.dst_protocol )
        else:
            print "CT_DP not ready yet for src to connect"

    def tunnelIsReady(self, req):
        """
        State 4:  Ready

        Extract covert data from request, send to ccp
        """
        end_of_req = req.find(const.END_HEADER)
        if end_of_req < 0:
            return (False, req)
        else:
            remainder = req[end_of_req + len(const.END_HEADER):]

        # Check that HTTP request contains covert data
        #
        header = http_util.get_header('GET /', req)
        if header == '-1':
            print "No covert data in http request, ignoring"
            return (True, remainder)

        # Pull out the covert data
        #
        hex_text        = header[ 0 : (len(header) - len(' HTTP/1.1') - const.URL_PADDING_HEX_LEN) ]
        cipher_text     = hex_text.decode("hex")
        auth_plain_text = self.rc4.update(cipher_text)
        hash_offset     = const.HTTPU_HEX_HASHLEN
        uri_offset      = hash_offset + len(const.HTTPU_HASHSEP)
        auth_text       = auth_plain_text[:hash_offset]
        plain_text      = auth_plain_text[uri_offset:]

        test_text = '%s%s%s' % (
                self.encoder.digest(plain_text), const.HTTPU_HASHSEP, plain_text)

        t = re.split(':', plain_text)
        count = t[0]
        plain_text = plain_text[len(count) + 1:]

        curr_count = int(count)
        if not self.curr_count:
            self.curr_count = curr_count
        elif self.curr_count != curr_count - 1:
            print "WE MISSED SOMETHING"
            self.exit(1)
        else:
            self.curr_count = curr_count

        if test_text != auth_plain_text:
            print "Integrity check failed, ignoring message"
            return

        if re.search(const.HTTP_UNI_CHAFF_URL_PATH, plain_text):
            return (True, remainder)

        # Forward the covert request to the CCP_DP
        #
        if not self.dst_protocol is None:
            self.dst_protocol.transport.write(plain_text)

        return (True, remainder)

class CT_DP(object):
    """
    DP side of CT
    """
    def __init__(self, srcaddr, dstaddr):
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.tunnels = {}
        self.producers = {}

        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory.srcaddr = srcaddr
        self.srcFactory.dstaddr = dstaddr
        self.srcFactory.ct_dp = self

        endpoint = endpoints.TCP4ServerEndpoint(
                reactor, srcaddr[1], interface=srcaddr[0] )
        endpoint.listen(self.srcFactory)

        self.mole = None

    def setMole(self, mole):
        self.mole = mole

    def getMole(self):
        return self.mole

    def tunnelMade(self, src_protocol, dst_protocol):
        """
        The SRC protocol calls this once it has received a connection
        and connects it to a DST flow.
        """

        # Store the host since it goes away before connectionLost is called
        #
        dst_protocol.host = str(dst_protocol.transport.getHost())
        self.tunnels[dst_protocol.host] = (src_protocol, dst_protocol)

        # We call this here in case setProducer was called before
        # we entered this function
        #
        if dst_protocol.host in self.producers:
            src_protocol.transport.registerProducer(
                self.producers[dst_protocol.host], True)

    def tunnelLost(self, src_protocol, dst_protocol):
        # Src protocol calls this once it receives a connectionLost,
        # We need to remove this tunnel from our structures
        #
        try:
            self.tunnels.pop(dst_protocol.host)
        except AttributeError:
            print "Exceptions.AttributeError: DstProtocol instance has no attribute 'host"

    def getTunnel(self, host):

        if not host in self.tunnels:
            return None
        return self.tunnels[host]

    def setProducer(self, host, producer):

        host = str(host)
        if not host in self.tunnels:
            return

        self.producers[host] = producer

        # We call this here as well as tunnelMade, as we don't know
        # which event will occur first
        #
        if host in self.tunnels:
            self.tunnels[host].src_protocol.transport.registerProducer(
                producer, True)

    def set_cm_close_callback(self, callback):
        self.srcFactory.cm_close_callback = callback



def main():
    log.startLogging(sys.stdout)

    ct_dp = CT_DP(('localhost', 80), ('localhost', 5002))
    reactor.run()

if __name__ == '__main__':
    main()

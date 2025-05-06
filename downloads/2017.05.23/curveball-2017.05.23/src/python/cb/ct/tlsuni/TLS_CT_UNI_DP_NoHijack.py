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

import array
import binascii
import datetime
import exceptions
import hashlib
import hmac
import logging
import os
import random
import re
import socket
import struct
import sys

import cb.bp
import cb.cssl
import cb.cssl.cssl
import cb.util.cblogging
import cb.util.cb_constants as const
import cb.util.http_util_req as http_util
from cb.mole.c_encode import HttpMoleCryptoEncoder

from twisted.internet import interfaces
from twisted.internet import reactor
import twisted.internet.endpoints as endpoints
from twisted.internet.protocol import Factory, Protocol
from zope.interface import implements


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
        We've lost our connection to the dst (CCP_DP)
        for some reason, close to the connection to the client
        as well
        """
        print "lost dst protocol connection"
        self.cc.transport.loseConnection()

    def dataReceived(self, new_data):
        """
        Read data from CCP_DP to CCP_client, to be sent via CT.
        """
        self.recv_buf += new_data
       
        if self.cc:
            self.cc.mole.enqueue(self.recv_buf)
            self.recv_buf = ''
        else:
            print "Could not enqueue mole data"


class SrcProtocol(Protocol):
    """
    Accepted connection from the client (via the TCP engine) to the DP side of
    the CT.
    """

    def __init__(self):

        self.dstFactory = None
        self.dst_protocol = None
        self.ct_dp = None
        self.mole = None
        self.recv_buf = ''

    def connectionMade(self):
        """
        TLSFUnilowMonitor has stepped through the Curveball handshake.
        Use the callback to get a handle for the TLSUniFlowMonitor, which
        knows the session key for the connection.
        """

        dstFactory = Factory()
        dstFactory.protocol = DstProtocol
        dstFactory.src_protocol = self

        endpoint = endpoints.TCP4ClientEndpoint(
                reactor, self.factory.dstaddr[0], self.factory.dstaddr[1])
        d = endpoint.connect(dstFactory)
        d.addCallback(self.dstConnected)

        self.mole = self.factory.ct_dp.getMole()

    def connectionLost(self, reason):
        """
        We've lost the connection to the src (client), shut down
        the connection to the dst (CCP_DP).
        """

        print "TLS CT_DP UNI connectionLost"
        
        if not self.dst_protocol is None:
            self.dst_protocol.transport.loseConnection()

        if not self.ct_dp is None:
            self.ct_dp.tunnelLost(self, self.dst_protocol)

        p = self.transport.getPeer()
        self.factory.cm_close_callback((p.host, p.port))

    def dstConnected(self, protocol):

        self.dst_protocol = protocol
        if self.ct_dp:
            self.ct_dp.tunnelMade(self, self.dst_protocol)

    def dataReceived(self, data):
        self.tunnelIsReady(data)

    def tunnelIsReady(self, buf):
       
        if self.dst_protocol == None:
            print "tls ct uni dp: dst protocol is none"
            return
        
        self.dst_protocol.transport.write(buf)

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
        self.srcFactory.cm_close_callback = None
        self.srcFactory.ct_dp = self

        endpoint = endpoints.TCP4ServerEndpoint(
                reactor, srcaddr[1], interface=srcaddr[0])
        endpoint.listen(self.srcFactory)

        self.mole = None

    def setMole(self, mole):
        self.mole = mole

    def getMole(self):
        return self.mole

    def tunnelMade(self, src_protocol, dst_protocol):
        """
        The SRC protocol calls this once it has received a connection
        and connect it to a DST flow.
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
        """
        The SRC protocol calls this once it receives a connectionLost,
        we need to remove this tunnel from our structures
        """

        print 'TLS UNI CT DP: TUNNEL HAS BEEN LOST'
        
        try:
            self.tunnels.pop(dst_protocol.host)
        except AttributeError:
            print "Exceptions.AttributeError: DstProtocol has no attribute 'host"

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
            self.tunnels[host].src_protocol.transport.registerProducer(producer, True)

    def set_cm_close_callback(self, callback):
        self.srcFactory.cm_close_callback = callback


if __name__ == '__main__':
    ct_dp = CT_DP(('localhost', 5001), ('localhost', 5002))

    reactor.run()



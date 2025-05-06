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
Implementation of the client side of the Covert Channel Protocol

The root class that implements the service side is the CCPService.
This class uses twisted to react to events.  As necessary, it creates
instances of CCPServiceWorker to manage connections between the CCPService
and the target service (i.e. a SOCKS5 server, or echo-server) and
CCPClientWorker to manage connections between the CCPService and a client
(an instance of CCPClient).
"""

import logging
import os
import socket
import sys
import time

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from zope.interface import implements
from twisted.internet import interfaces
from twisted.internet import reactor

import cb.util.cblogging
from cb.ccp.ccp import CCPMessage

DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))

def log_debug(msg):
    print >> sys.stderr, "ccp_dp: %s" % msg

def log_error(msg):
    print >> sys.stderr, "ccp_dp: ERROR: %s" % msg

class DstProtocol(Protocol):
    """
    Connects to SOCKS
    """

    def __init__(self):

        self.log = logging.getLogger('cb.ccp_dp')
        self.log.debug('%s created new CCPServerWorker' % str(time.time()))
        self.buff = ''

        # These are defined once the connection is made
        self._socks5_addr = None
        self._cvpn_addr = None
        self._src_protocol = None
        self._conn_id = None

    def connectionLost(self, reason):
        """
        When a connection to the service is lost (for any reason) we need to
        inform the client that the connection is gone.
        """
        self.log.debug("Closing connection")

        # Need to inform the client end that
        # this connection has closed
        #
        close_msg = CCPMessage.close_msg(self._conn_id)
        self._src_protocol.transport.write(close_msg.pack())

    def dataReceived(self, data):
        """
        When the service socket is readable, read a small amount of data
        from it, wrap it up in a CCPMessage, and pass it to the client
        sock for this connection.

        It's not an error if the read is incomplete, and handle_close will
        clean up implicitly if there is a zero-length recv.
        """
        
        while len(data) > 0:
            chunk = data[:4096]
            msg = CCPMessage.data_recv(self._conn_id, chunk)
            #TODO does the CCPCLientWorker's sock and conid need
            # to be updated here?
            self._src_protocol.transport.write(msg.pack())
            data = data[4096:]

    def connectionMade(self):
        self._socks5_addr = self.factory.socks5_addr
        self._cvpn_addr = self.factory.cvpn_addr
        self._src_protocol = self.factory.src_protocol
        self._conn_id = self.factory.connid

        self.factory.src_protocol.dstConnected(self)
        
        self.log.debug("Made connection for connid: %d" % self.factory.connid)

class SrcProtocol(Protocol):
    """
    Handler for a client (src) connection

    In the dst->src direction, this class acts as a
    Twisted producer for the CT's SRC connection.  When the CT's
    SRC connection slows down, it tells this class to pause
    production, which in turn tells all of the ccp_dp's DST
    transports for the tunnel to pause until resume is called.
    """
    implements(interfaces.IPushProducer)

    def __init__(self):

        self._connid2dst_protocol = {}
        self._read_buffer = ''
        self.buff = {}

        self.log = logging.getLogger('cb.ccp_dp')

        # These are defined once the connection is made
        self._socks5_addr = None
        self._cvpn_addr = None
        self._con_mon = None
        self._src_addr = None

    def dstConnected(self, protocol):
        """
        A new DST connection (to the proxy server) has been made
        """

        self._connid2dst_protocol[protocol._conn_id] = protocol
        open_ack_msg = CCPMessage.open_ack_msg(protocol._conn_id)

        # ACK the src so that it starts sending data
        self.transport.write(open_ack_msg.pack())

    def con_error(self, failure):
        print 'unable to connect to socks/vpn server'
        self.log.warn("Unable to socks/vpn server: %s" % failure.getTraceback())

    def dataReceived(self, new_data):
        """
        Deal with a message coming from a client.
        """
        
        self._read_buffer += new_data
        
        # Read a CCPMessage from the client socket.  If the attempt fails, or
        # the resulting message is a CLOSE, then kill the corresponding
        # connection.
        #
        # Otherwise, perform the requested action.        
        try:
            (msgs, self._read_buffer) = CCPMessage.recv(self._read_buffer)           
        except Exception as inst:
            log_error("Exception reading %d bytes of new_data" % len(new_data))
            log_error("%s" % inst)
            raise

        for msg in msgs:
            msg_type = msg.get_msg_type()
            connid = msg.get_conn_id()
            if ((msg_type == CCPMessage.OPEN_SOCKS5_CONN) or
                    (msg_type == CCPMessage.OPEN_CVPN_CONN)):
                # open a new connection

                # FIXME / TODO - open a connection to the service.
                # If we can't open a connection to the service, then
                # there's nothing we can do.  (we might need a separate
                # way to signal an error before we even get underway)
                dstFactory = Factory()
                dstFactory.protocol = DstProtocol
                dstFactory.socks5_addr = self._socks5_addr
                dstFactory.cvpn_addr = self._cvpn_addr
                dstFactory.src_protocol = self
                dstFactory.connid = connid

                if msg_type == CCPMessage.OPEN_SOCKS5_CONN:
                    dst_addr = self._socks5_addr
                elif msg_type == CCPMessage.OPEN_CVPN_CONN:
                    dst_addr = self._cvpn_addr
                else:
                    # TODO: whoops!
                    pass

                endpoint = endpoints.TCP4ClientEndpoint(reactor,
                        dst_addr[0], dst_addr[1])

                d = endpoint.connect(dstFactory)
                d.addErrback(self.con_error)

            elif msg_type == CCPMessage.CLOSE_CONNECTION:
                # shut down a connection
                dst_protocol = self._connid2dst_protocol.pop(connid)
                dst_protocol.transport.loseConnection()

            elif msg_type == CCPMessage.DATA_SEND:

                # Drop chaff.
                #
                if connid == CCPMessage.CHAFF_CONN_ID:
                    # print 'Dropping chaff len %d' % len(msg.get_data())
                    continue

                data = msg.get_data()
                
                # Figure out which service socket corresponds to the connid
                if not connid in self._connid2dst_protocol:
                    # Drop unexpected data
                    print "CCP: unexpected data"
                    return
                else:
                    dst_protocol = self._connid2dst_protocol[connid]
                    dst_protocol.transport.write(data)
                    #print "CCP: writing data"
            else:
                # TODO whoops!
                pass

    def connectionLost(self, reason):

        # Close the service sockets
        for protocol in self._connid2dst_protocol.values():
            try:
                protocol.transport.loseConnection()
            except Exception, err:
                self.log.warn("unexpected exception closing lost connection (%s)", str(err))

        self.log.debug("ccp: connectionLost, will let CT_DP trigger connection close")
        #if not self._con_mon is None:
        #    self._con_mon.forward_close(self._src_addr)

    def pauseProducing(self):
        """ Called when the CT can't send anymore to the src """
        self.log.debug("Pausing production")

        for protocol in self._connid2dst_protocol.itervalues():
            try:
                protocol.transport.pauseProducing()
            except Exception, err:
                self.log.warn("unexpected exc (%s)", str(err))

    def resumeProducing(self):
        """ Called when the CT src is ready for more data """

        self.log.debug("Resuming production")
        for protocol in self._connid2dst_protocol.itervalues():

            # twisted gets upset if we try to resume a connection
            # that is disconnected or in the process of disconnecting
            #
            if (protocol.transport.connected and
                    (not protocol.transport.disconnecting)):
                try:
                    protocol.transport.resumeProducing()
                except Exception, err:
                    self.log.warn("unexpected exc (%s)", str(err))
            else:
                self.log.warn("resumeProducing on dead conn (%s)",
                        str(protocol))

    def stopProducing(self):
        self.pauseProducing()

    def connectionMade(self):
        """
        A src has connected to us
        """
        self._socks5_addr = self.factory._socks5_addr
        self._cvpn_addr = self.factory._cvpn_addr
        self._con_mon = self.factory._con_mon
        self._ct_dps = self.factory._ct_dps
        p = self.transport.getPeer()
        self._src_addr = (p.host, p.port)

        # Tell the CT that we're the producer for this tunnel
        # This way we can slow recvs from the proxy when the
        # link to the client can't handle it
        if self._ct_dps:
            # We don't know which CT_DP this actually belongs to..
            # http or tls or ?  so we tell them all!
            for ct_dp in self._ct_dps.itervalues():
                ct_dp.setProducer(self.transport.getPeer(), self)

class CCP_DP(object):
    """
    Server side of CCP
    """

    def __init__(self, src_addr, socks5_addr, tls, con_mon=None, ct_dps=None,
            cvpn_addr=None):
        """
        src_addr - the (address, port) that this service listens on
        for new connections.  It must be a local address that can be
        bind'd by this process.

        socks5_addr - the (address, port) to which SOCKS5 connections are
        established.

        tls - whether or not to use TLS (not currently supported)

        cvpn_addr - the (address, port) to which CVPN connections are
        established.
        """

        self._socks5_addr = socks5_addr
        self._cvpn_addr = cvpn_addr

        # CT_DP reference
        self._ct_dps = ct_dps

        # Connection Monitor reference
        self._con_mon = con_mon

        # 2. create the local socket; bind, listen.
        #
        # Note that we don't try to connect to the service addr yet.
        # We put this off until we have actual clients, which means that
        # the service addr doesn't need to be active yet.  (it does mean
        # that we might fall over with a thud later, if clients appear and
        # there's nothing to service them)

        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory._socks5_addr = self._socks5_addr
        self.srcFactory._cvpn_addr = self._cvpn_addr
        self.srcFactory._con_mon = self._con_mon
        self.srcFactory._ct_dps = self._ct_dps

        endpoint = endpoints.TCP4ServerEndpoint(
                reactor, src_addr[1], interface=src_addr[0])
        endpoint.listen(self.srcFactory)
        self.log = logging.getLogger('cb.ccp_dp')

if __name__ == '__main__':
    def test_main():
        CCP_DP(('', 5001), ('localhost', 5002), False, None,
                cvpn_addr=('localhost', 5003))
        reactor.run()

    exit(test_main())

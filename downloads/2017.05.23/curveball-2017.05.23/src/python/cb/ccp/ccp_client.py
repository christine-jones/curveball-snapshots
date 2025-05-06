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
"""

import binascii
import logging
import math
import os
import re
import time

from twisted.internet.protocol import Factory, Protocol, ReconnectingClientFactory
import twisted.internet.endpoints as endpoints
from zope.interface import implements
from twisted.internet import interfaces
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
import cb.util.http_util_req as http_util

import cb.util.cb_constants as const
import cb.util.cblogging
import cb.util.twisted_exit

from cb.ccp.ccp import CCPMessage
from cb.util.signals import Signals

from cb.mole.c_encode import HttpMoleCryptoEncoder

class SrcProtocol(Protocol):
    """ Link to SRC side from CCP_Client (firefox/jabber/etc...)

        Data received from SRC endpoint should then be written
        to the destination transport after processing """

    def __init__(self):
        self.log = logging.getLogger('cb.ccp')
        self.open_ack = False
        self.buffer = ''
        self.conn_id = None

    def connectionMade(self):
        """
        We've successfully connected to a new client, send a setup msg
        """
        self.conn_id = (self.factory.last_conn_id + 1) & 0xffffffff
        self.factory.last_conn_id = self.conn_id
        self.factory.ccp_client.srcConnected(self)

        if self.factory.conn_type == CCPMessage.OPEN_SOCKS5_CONN:
            setup_msg = CCPMessage.open_socks_msg(self.conn_id)
        elif self.factory.conn_type == CCPMessage.OPEN_CVPN_CONN:
            setup_msg = CCPMessage.open_cvpn_msg(self.conn_id)
        else:
            # TODO: Unknown connection type: whoops.
            pass
        
        # Write directly to the transport, avoiding
        # write_dst so that it doesn't get buffered
        #
        proto = self.factory.ccp_client.getDstProtocol()
        proto.transport.write(setup_msg.pack())

    def dataReceived(self, data):
        """
        The client has written something, so wrap it up in a CCPMessage and
        send it along.
        """

        while len(data) > 0:
            chunk = data[:4096]            
            msg = CCPMessage.data_send(self.conn_id, chunk)
            self.write_dst(msg.pack())
            data = data[4096:]

    def open_ack_recvd(self):
        """
        The server has acked our open, time to open the sending
        gates and send anything we've buffered up until now
        """       
        self.open_ack = True
        if self.buffer:
            self.write_dst(self.buffer)
            self.buffer = ''

    def write_dst(self, data):
        
        if not self.open_ack:
            self.buffer += data
        else:
            proto = self.factory.ccp_client.getDstProtocol()
            proto.transport.write(data)
            self.factory.ccp_client.update_txbytes(len(data))

    def connectionLost(self, reason):
        """
        The client has closed its connection to us.  Tell the terminal,
        and then clean up.
        """
        msg = CCPMessage.close_msg(self.conn_id)
        self.write_dst(msg.pack())
        self.factory.ccp_client.srcDisconnected(self)



class DstProtocol(Protocol):
    """
    Link to the DST side of the CCP_Client (the CT_Client).
    """
    def __init__(self):
        self.read_buffer = ''
        self.dec_tls_buffer = ''
        self.log = logging.getLogger('cb.ccp')
        self.tls_uni_mole_decoder = None
        self.tls_uni_hdshake_resp = 0
        self.num_chaff_received = 0
        self.num_data_received = 0
        self.tunnel_chaff = None

    def connectionMade(self):
        """
        Tell the ccp_client that we've connected to the CT
        """

        if self.factory.tunnel_type == 'tls-uni':
            # The TLS-UNI Handshake is not completed
            # Unlike the other tunnels, for TLS-UNI, the final check
            # for the completion of the handshake occurs in ccp_client
            #
            pass
        else:
            print "Client: Connected to CT_Client"

        self.factory.ccp_client.dstConnected(self)
  
        # We set the host address to foobar.org since we're only using 
        # this encoder for decryption
        #
        if self.factory.tunnel_type == 'tls-uni':
            self.tls_uni_mole = HttpMoleCryptoEncoder(
                    'foobar.org', self.factory.sentinel[16 : ])

    def chaffling(self):
        """
        The TLS_UNI client generates chaff directly in ccp_client. This is
        unlike the HTTP_UNI client which generates chaff
        in HTTP_CT_UNI_CLIENT.py. The TLS_UNI client generates chaff here
        for ease of implementation: while chaff could be generated in
        client_agent.c, this would require significant restructuring
        (particularly as client_agent.c is shared by both the TLS_UNI
        and TLS_BI clients)

        TODO: a nice feature would be to be able to vary the length of the
        chaff, e.g., for traffic shaping.
        """

        chaff_txt = const.TLS_UNI_CHAFF_URL_PATH
        chaff_msg = CCPMessage.chaff_msg(len(chaff_txt), buf=chaff_txt)
        msg_buf = chaff_msg.pack()

        cnt = 4

        if (self.num_chaff_received < 5) or (self.num_data_received > 0):
            cnt += 20
        if self.num_data_received > 1:
            cnt += 20
        if self.num_data_received > 2:
            cnt += 20
        if self.num_data_received > 5:
            cnt+= 40

        # Can do more here.
        #
        # Can also divide the looping call time interval by 3

        # print 'chaff cnt %d num_data_received %d' % (
        #         cnt, self.num_data_received)
        total_buf = msg_buf * cnt

        proto = self.factory.ccp_client.getDstProtocol()
        proto.transport.write(total_buf)

        self.factory.ccp_client.update_txbytes(len(total_buf))

    def slow_chaffling(self):
        """
        The TLS_UNI client generates chaff directly in ccp_client. This is
        unlike the HTTP_UNI client which generates chaff
        in HTTP_CT_UNI_CLIENT.py. The TLS_UNI client generates chaff here
        for ease of implementation: while chaff could be generated in
        client_agent.c, this would require significant restructuring
        (particularly as client_agent.c is shared by both the TLS_UNI
        and TLS_BI clients)

        TODO: a nice feature would be to be able to vary the length of the
        chaff, e.g., for traffic shaping.
        """

        chaff_txt = const.TLS_UNI_CHAFF_URL_PATH
        chaff_msg = CCPMessage.chaff_msg(len(chaff_txt), buf=chaff_txt)
        msg_buf = chaff_msg.pack()

        cnt = 1

        if self.num_chaff_received < 5:
            cnt += 1

        if self.num_data_received > 0:
            cnt += 2
        if self.num_data_received > 1:
            cnt += 2
        if self.num_data_received > 2:
            cnt += 2
        if self.num_data_received > 5:
            cnt+= 4

        total_buf = msg_buf * cnt

        proto = self.factory.ccp_client.getDstProtocol()
        proto.transport.write(total_buf)

        self.factory.ccp_client.update_txbytes(len(total_buf))

    def dataReceived(self, data):
        """
        When a new CCP message arrives from the dst, handle it.
        """

        if self.factory.tunnel_type == 'tls-uni':
            data = self.process_TLS_uni_data(data)

        # Now we can process the ccp_messages in the data
        #
        self.read_buffer += data
        self.factory.ccp_client.update_rxbytes(len(data))

        (msgs, self.read_buffer) = CCPMessage.recv(self.read_buffer)

        for msg in msgs:
            msg_type = msg.get_msg_type()
            msg_conn_id = msg.get_conn_id()
            proto = self.factory.ccp_client.getSrcProtocol(msg_conn_id)
            if proto is None:
                # Either a close msg or some data from a socket
                # we no longer care about
                continue

            if msg_type == CCPMessage.DATA_RECV:
                msg_data = msg.get_data()
                proto.transport.write(msg_data)
            elif msg_type == CCPMessage.CLOSE_CONNECTION:
                proto.transport.loseConnection()
            elif msg_type == CCPMessage.OPEN_CONNECTION_ACK:
                proto.open_ack_recvd()
            else:
                self.log.warn('received unknown CCP message type from CT: %s' % msg)

        # Use the self.factory.ccp_client data to figure out where it should go
        # self.otherProtocol.transport.write(data)

    def process_TLS_uni_data(self, data):
        """
        Unmole each mole url in the data, one by one

        Note that there is chaff in two locations
        1. There are ccp chaff messages. These solely contain chaff
        2. The mole urls: these may be purely data, data+chaff (in the case
           that there was insufficient data to fill a packet), or purely chaff
        """

        self.dec_tls_buffer += data
        data = ""

        if self.tunnel_chaff == None:
            self.tunnel_chaff = LoopingCall(self.chaffling)
            self.tunnel_chaff.start(const.TLS_SEND_CHAFF_INTERVAL)

        while True:

            (self.dec_tls_buffer, http_resp, resp_body, unzip_resp_body, status
                    ) = http_util.extract_http_resp(
                            self.dec_tls_buffer, const.HTTP_UNI_TUNNEL)

            if status == -1 or http_resp == None:
                return data

            [status, dec_resp, enc_resp
                    ] = self.tls_uni_mole.decode_response(http_resp, commit=False)

            # If we got an http response, but it doesn't decode, bail out
            #
            if status == -1:
                print 'Error: no DR on path?'
                try:
                    reactor.stop()
                except:
                    # Eat the exception; we're already shutting down
                    pass
                return ''

            if dec_resp == "":
                self.num_chaff_received += 1
                self.num_data_received = 0
            else:
                self.num_data_received += 1
                self.num_chaff_received = 0

            if (self.factory.tls_uni_hdshake_done == False and
                self.check_for_tlsuni_welcome(dec_resp)):
                self.factory.tls_uni_hdshake_done = True
            else:
                data += dec_resp

    def check_for_tlsuni_welcome(self, dec_resp):

        try:
            dec_resp.index(const.TLSUNI_CURVEBALLHELLO)
            self.factory.ccp_client.signals.emit('CT_CONNECTED')
            print "Client: Connected to CT_Client"
            print "CCP has connected to CT, starting CCP server... "
            print 'Curveball ready'
            return True

        except ValueError:
            print "Error: response does not contain welcome"
            return False

    def connectionLost(self, reason):
        self.log.warning("DstProtocol lost connection to CT (%s)",
                (str(reason.getErrorMessage())))
        self.factory.ccp_client.dstDisconnected(self)

class CCPClient(object):
    """
    CCPClient multiplexes srcs (e.g., firefox/jabber) to a single dst (the CT_Client)
    by wrapping flow data inside of CCP messages.

    The transport to the CT acts as a consumer and will tell the CCPClient
    when to pause production from the srcs.  Note that flow control
    is from src->dst only, we assume that dst->src does not require flow control
    """
    implements(interfaces.IPushProducer)

    def __init__(self, src_addr, dst_addr, tunnel_type, sentinel, tls,
            conn_type=CCPMessage.OPEN_SOCKS5_CONN):
        """
        src_addr - the (address, port) of the local entry point.
        It must be a local address that can be bind'd by this process.

        dst_addr - the (address, port) of the destination.

        tls - whether or not to use TLS (not currently supported)

        conn_type=CCPMessage.OPEN_SOCKS5_CONN - the type of connection
        to create.
        """

        self.connections = {}

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.tunnel_type = tunnel_type
        self.tls_uni_hdshake_done = False
        self.sentinel = sentinel
        
        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory.ccp_client = self
        self.srcFactory.conn_type = conn_type
        self.srcFactory.last_conn_id = (os.getpid() << 8)
        self.srcFactory.tunnel_type = self.tunnel_type
        self.srcFactory.tls_uni_hdshake_done = self.tls_uni_hdshake_done
        
        self.dstFactory = Factory()
        self.dstFactory.protocol = DstProtocol
        self.dstFactory.ccp_client = self
        self.dstFactory.tunnel_type = self.tunnel_type
        self.dstFactory.tls_uni_hdshake_done = self.tls_uni_hdshake_done
        self.dstFactory.sentinel = self.sentinel

        self.connectDst()

        self.log = logging.getLogger('cb.ccp')
        self.signals = Signals()

        self.tput_start = 0
        self.tput_delta = 1.0
        self.tput_txbytes = 0
        self.tput_rxbytes = 0
        self.update_tput()

    def update_tput(self):
        curtime = time.time()#math.floor(time.time())
        if curtime >= self.tput_delta + self.tput_start:
            tx_kbps = 8.0 * float(self.tput_txbytes) / float(self.tput_delta) / 1024.0
            rx_kbps = 8.0 * float(self.tput_rxbytes) / float(self.tput_delta) / 1024.0
            self.signals.emit('TPUT_UPDATE', (tx_kbps, rx_kbps))

            self.tput_txbytes = 0
            self.tput_rxbytes = 0
            self.tput_start = curtime
            
        reactor.callLater(self.tput_delta, self.update_tput)

    def update_txbytes(self, bytes):
        self.tput_txbytes += bytes

    def update_rxbytes(self, bytes):
        self.tput_rxbytes += bytes

    def connectDst(self):
        dst_endpoint = endpoints.TCP4ClientEndpoint(
                reactor, self.dst_addr[0], self.dst_addr[1], timeout = 1)
        d = dst_endpoint.connect(self.dstFactory)
        d.addErrback(self.dstConnectionFailed)

    def dstConnectionFailed(self, reason):
        """
        If we couldn't connect to the CT, try again in a bit
        """
        reactor.callLater(1, self.connectDst)
        # try:
        #     reactor.stop()
        # except BaseException, _exc:
        #     pass

    def dstServerFailed(self, reason):
        print "Can't bind to server socket: %s" % str(reason.getErrorMessage())
        try:
            cb.util.twisted_exit.EXIT_STATUS = 1
            reactor.stop()
        except BaseException, _exc:
            pass

    def pauseProducing(self):
        """
        The dst is telling us to hold up, forward the message
        on to the srcs.  Note that this could be improved with
        some kind of fair queueing scheme instead of brute force
        blocking everyone.
        """
        for proto in self.connections.itervalues():
            try:
                proto.transport.pauseProducing()
            except Exception, err:
                self.log.warn("unexpected exc (%s)", str(err))

    def resumeProducing(self):
        """
        The dst says that it's ready for more traffic.
        """

        # twisted gets upset if we try to resume a connection
        # that is disconnected or in the process of disconnecting,
        # so be defensive
        #
        for proto in self.connections.itervalues():
            if (proto.transport.connected and
                    (not proto.transport.disconnecting)):
                try:
                    proto.transport.resumeProducing()
                except Exception, err:
                    self.log.warn("unexpected exc (%s)", str(err))
            else:
                self.log.warn("resumeProducing on dead conn (%s)",
                        str(proto.transport))

    def stopProducing(self):
        self.pauseProducing()

    def dstConnected(self, protocol):
        """
        We've connected to the dst, start listening
        for srcs
        """

        if self.tunnel_type == 'tls-uni':   
            pass # Handshake not completed at this point for tls-uni
        else:
            print "CCP has connected to CT, starting CCP server..."
        
        self.dstProto = protocol

        # We're the producer for the dst transport
        protocol.transport.registerProducer(self, True)

        # Next let's get the server going
        endpoint = endpoints.TCP4ServerEndpoint(reactor,
                self.src_addr[1], interface=self.src_addr[0])
        deferred = endpoint.listen(self.srcFactory)
        deferred.addErrback(self.dstServerFailed)

        if self.tunnel_type == 'tls-uni':   
            pass # Handshake not completed at this point for tls-uni
        else:
            self.signals.emit('CT_CONNECTED')
            print 'Curveball ready'

    def dstDisconnected(self, protocol):
        """
        When the connection to the dst (CT) is broken, we need to inform any
        clients we have that the connection is gone.
        """

        self.log.warning("Closing connections to srcs after dst lost connection to CT")
        for proto in self.connections.itervalues():
            try:
                proto.transport.loseConnection()
            except Exception, err:
                self.log.warn("unexpected exc (%s)", str(err))

        # Let's reconnect
        # self.connectDst()
        print "Not attempting to reconnect"

    def srcConnected(self, protocol):
        """
        A src connected, take note
        """
        self.connections[protocol.conn_id] = protocol

    def srcDisconnected(self, protocol):
        """
        A src disconnected, take note
        """
        self.connections.pop(protocol.conn_id)

    def getSrcProtocol(self, conn_id):
        """
        Given a CCP connection id, find the src protocol
        """
        if not conn_id in self.connections:
            return None
        return self.connections[conn_id]

    def getDstProtocol(self):
        """
        Get the dst protocol
        """
        return self.dstProto
    
    def send_chaff(self, length, buf=''):
        """
        Send chaff of the given length to the DP.  If buf is not empty,
        and is long enough, then use it for the chaff.  If the buf is
        empty (or not long enough) then use buf and then fill the rest
        of the chaff with '+' characters.  (See CCPMessage.chaff_msg())

        Returns the number of bytes of chaff sent (not including the msg
        header).  This may be zero -- it is legal to send a chaff message
        that consists of just a header.  If the connection is not ready
        to accept chaff, then returns -1.
        """
        # Don't push chaff through until the dstProto is set.
        try:
            proto = self.getDstProtocol()
        except AttributeError, _exc:
            return -1

        msg = CCPMessage.chaff_msg(length, buf=buf)
        raw_buf = msg.pack()

        proto.transport.write(raw_buf)
        self.update_txbytes(len(raw_buf))

        return length



if __name__ == '__main__': # Test
    from twisted.internet.task import LoopingCall

    def test_main():
        """
        Scaffolding for a unit test.  For now it just
        creates a client
        """

        client = CCPClient(('', 5000), ('localhost', 5001), False)

        def chaffling():
            #print "sending chaff!"
            client.send_chaff(10)

        loop = LoopingCall(chaffling)
        loop.start(5)

        reactor.run()

    exit(test_main())



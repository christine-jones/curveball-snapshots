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
Server end of the HTTP covert channel

Connects to the Server_Stub

Listens for a connection from the HTTP_CT_Client, when one arrives,
it plumbs the two together.

The protocol for setting up the new session keys for the communication between
the Client and the DP is as follows:

1. The Client sends a generated GET request to the decoy dest using '/' as
the site and an if-none-match containing the sentinel.

2. The DP sends a generated HTTP response containing a challenge as the
packet payload.

3. The Client sends back another generated GET request containing the challenge
response, again in the if-none-match field.

4. The DP verifies the challenge response and sends back a 'welcome to curveball',
again as the packet payload.

5. Once the client gets a 'welcome to curveball' it then uses the cookies in
generated get requests to send covert data to the DP, while the DP uses the payload
of gnerated HTTP responses to send covert data to the client.

"""
import exceptions
import hashlib
import hmac
import logging
import os
import socket
import string

from M2Crypto import RSA, BIO, EVP

import sys
sys.path.append('../../../../python')
sys.path.append('../../../../sentinels')

from cb.noc.gen_sentinels import create_date_hmac_str
from cb.noc.gen_sentinels import create_sentinel
from cb.noc.check_sentinel import CheckSentinel
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor
import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cblogging
import cb.util.cb_constants as const
import cb.util.cb_constants_dp as const_dp
import cb.util.cb_random as cb_random
import cb.util.security_util as security_util
import cb.util.privkey_util as privkey_util
import cb.util.http_util_req as http_util
import cb.util.http_util_resp as http_resp

from twisted.python import log



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

        #print "got new data from ccp! [%s]" % str(self.recv_buf)

        # TODO: error check
        if self.cc:
            self.cc.ccdp_to_cc(self.recv_buf)
            self.recv_buf = ''
        else:
            # FIXME: very strange situation.  We should not be getting anything
            # from CCP until we are connected.  (the first thing that CCP sends
            # should be a response to something the client did)
            print('got data from ccp before ct connection?')



class SrcProtocol(Protocol):

    def __init__(self):

        global ccp_port

        self.log = logging.getLogger('cb.ct.http')

        self.sentinel_hex = None

        self.privkey_dp = None
        self.nonce_client = None
        self.nonce_dp = None
        self.premaster = None

        self.client_key = None
        self.dp_key = None

        self.client_hash = None
        self.dp_hash = None

        self.dstFactory = None
        self.dst_protocol = None # DstProtocol instance
        self.client_data = None # Sentinel we're expecting
        self.toServer = ''
        self.recv_buf = ''
        self.data_recv = ''
        self.data_len = 0
        self.state = const_dp.STATE_4_5
        self.buf = ''

        self.seqNum_D2C_Rand = cb_random.gen_rand_bytes(
            self, const.SEQ_NUM_RAND_BYTE_LEN)
        self.seqNum_C2D_Rand = None
        self.seqNum_D2C_Counter = 0
        self.seqNum_C2D_Counter = 0

        self.server_name = 'Server: Apache' + const.END_LINE
        self.content_type = 'Content-Type: ' + 'text/html; charset=UTF-8' + const.END_LINE

    def connectionMade(self):
        """
        We've connected to a src.  Get the expected sentinel from the
        connection monitor and make a connection to the dst (CCP).
        """

        p = self.transport.getPeer()
        self.log.debug('HTTP_CT_DP.SrcProtocol: connectionMade (%s, %s)'
                       % (str(p.host), str(p.port)))
        self.client_data = self.factory.cm_http_callback( (p.host, p.port) )

        i1 = const.FULL_SENTINEL_HEX_LEN
        i2 = i1 + const.NONCE_CLIENT_BYTE_LEN
        i3 = i2 + const.NONCE_DP_BYTE_LEN
        i4 = i3 + const.PREMASTER_BYTE_LEN
        i5 = i4 + const.DECOUPLED_ID_BYTE_LEN
        i6 = i5 + const.SEQ_NUM_RAND_BYTE_LEN

        self.sentinel_hex    = self.client_data[ 0  : i1 ]
        self.nonce_client    = self.client_data[ i1 : i2 ]
        self.nonce_dp        = self.client_data[ i2 : i3 ]
        self.premaster       = self.client_data[ i3 : i4 ]
        self.decoupled_ID    = self.client_data[ i4 : i5 ]
        self.seqNum_C2D_Rand = self.client_data[ i5 : i6 ]
        header_field_values  = self.client_data[ i6 :    ]

        val = header_field_values.split(const.END_LINE)
        if len(val) == 2:
            content_type_temp  = val[0]
            server_name_temp   = val[1]
        else:
            print "did not receive all tunnel params from connection_monitor"
            self.cc.transport.loseConnection()

        if content_type_temp != '':
            self.content_type = 'Content-Type: ' + content_type_temp + const.END_LINE
        if server_name_temp != '':
            self.server_name = 'Server: ' + server_name_temp + const.END_LINE

        dstFactory = Factory()
        dstFactory.protocol = DstProtocol
        dstFactory.src_protocol = self

        endpoint = endpoints.TCP4ClientEndpoint(
                reactor, self.factory.dstaddr[0], self.factory.dstaddr[1])
        d = endpoint.connect(dstFactory)
        d.addCallback(self.dstConnected)


    def connectionLost(self, reason):
        """
        We've lost the connection to the src (client), shut down
        the connection to the dst (CCP_DP).
        """

        self.log.debug('HTTP_CT_DP.SrcProtocol: connectionLost')

        if not self.dst_protocol is None:
            self.dst_protocol.transport.loseConnection()
            self.factory.ct_dp.tunnelLost(self, self.dst_protocol)

        p = self.transport.getPeer()
        self.factory.cm_close_callback((p.host, p.port))


    def dstConnected(self, protocol):

        self.log.debug('HTTP_CT_DP.SrcProtocol: dstConnected')
        self.dst_protocol = protocol
        self.factory.ct_dp.tunnelMade(self, self.dst_protocol)


    def dataReceived(self, data):

        self.state_machine_input(data)


    def ccdp_to_cc(self, buf):
        """
        State 6: Sending covert data from DP in http response

          A.     Payload :  SeqNum_D2C +
          B.                HMAC_DP( R3 ) +
          C.                E_DP( R3 )

         R3 = Salt_4     +
              SeqNum_D2C +
              CovertData
        """

        # A.  SeqNum_D2C
        #
        self.seqNum_D2C_Counter = self.seqNum_D2C_Counter + 1
        s = self.seqNum_D2C_Rand + str( self.seqNum_D2C_Counter )
        seqNum_D2C = hmac.new(
            s, self.dp_hash, hashlib.sha256 ).digest()

        # B. HMAC_DP( Salt_4 + SeqNum_D2C +CovertData )
        #
        salt_4 = cb_random.gen_rand_bytes(self, const.SALT_BYTE_LEN)
        text = ( salt_4 + seqNum_D2C + buf )
        auth_text = hmac.new( text, self.dp_hash, hashlib.sha256 ).digest()

        # C. E_DP( Salt_4 + SeqNum_D2C + CovertData )
        #
        resp = http_resp.create_http_resp(self, self.dp_key,
                seqNum_D2C + auth_text, self.server_name,
                self.content_type, text)

        try:
            self.transport.write(resp)
        except socket.error, why:
            self.log.debug('HTTP_CT_DP.SrcProtocol.ccdp_to_cc: socket error: %s' % str(why))
            pass


    def state_machine_input(self, data):
        """
        Process data based on state
        """

        self.log.debug("HTTP_CT_DP Received data")

        if self.state == const_dp.STATE_4_5:
            self.send_response_to_premaster(data)

        elif self.state == const_dp.STATE_6:
            self.tunnel_is_ready(data)


    def send_response_to_premaster(self, data):
        """
        State 4.5:  Send response to premaster

         A.     Payload :  HMAC_DP( R1 ) +
         B.                E_DP( R1 )

          R1 = Salt_2               +
               SeqNum_D2C_Rand      +
               welcome to curveball
        """

        # Compute new keys
        #
        [ self.client_key,
          self.dp_key,
          self.client_hash,
          self.dp_hash ] = security_util.compute_keys(
            self, self.premaster, self.nonce_client, self.nonce_dp)

        # A. HMAC_DP( Salt_2 + SeqNum_D2C_Rand + welcome to curveball )
        #
        salt_2 = cb_random.gen_rand_bytes( self, const.SALT_BYTE_LEN )

        text = ( salt_2 +
                 self.seqNum_D2C_Rand +
                 "welcome to curveball" )

        auth_text = hmac.new( text, self.dp_hash, hashlib.sha256 ).digest()


        # B. E_DP( Salt_2 + SeqNum_D2C_Rand + welcome to curveball )
        #
        resp = http_resp.create_http_resp( self, self.dp_key,
                auth_text, self.server_name, self.content_type, text)

        self.transport.write( resp )

        # New state
        #
        self.state = const_dp.STATE_6

    def tunnel_is_ready(self, data):
        """
        State 6:  Ready

        Extract covert data from request
        """

        self.buf += data

        while True:
            (self.buf, rec) = http_util.extract_http_req(self, self.buf)
            if rec is None:
                break

            # Check that HTTP request contains covert data
            #
            header = http_util.get_header('GET /', rec)
            if header == '-1':
                print "No covert data in http request, ignoring"
                return

            # Pull out the covert data
            #
            if len(header) <= len(' HTTP/1.1'):
                return

            hex_text = header[ 0 : (len(header)-len(' HTTP/1.1')) ]

            # Separate the sequence number, hmac, and encrypted text
            #
            try:
                auth_enc_text = hex_text.decode("hex")
            except TypeError:
                print 'Error: text is not in hex'
                return

            l1 = const.HASH_BYTE_LEN
            l2 = l1 + const.HASH_BYTE_LEN

            seqNum_C2D = auth_enc_text[    : l1 ]
            auth_text  = auth_enc_text[ l1 : l2 ]
            enc_text   = auth_enc_text[ l2 :    ]

            # Check that seq number tag on pkt matches expected seq number
            #
            self.seqNum_C2D_Counter = self.seqNum_C2D_Counter + 1
            s = self.seqNum_C2D_Rand + str( self.seqNum_C2D_Counter )
            seqNum_C2D__ = hmac.new(
                s, self.client_hash, hashlib.sha256 ).digest()

            if ( seqNum_C2D__ != seqNum_C2D ):
                self.seqNum_C2D_Counter = self.seqNum_C2D_Counter - 1
                print "Error with Sequence Number tag on packet"
                return

            # Decrypt text
            #
            text = security_util.decrypt_text(
               self, enc_text , self.client_key, True, False, False)

            if text == -1:
                return

            # Check that HMAC is correct
            #
            auth_text_ = hmac.new( text, self.client_hash, hashlib.sha256 ).digest()
            if ( auth_text_ != auth_text ):
                print "Error with hmac"
                return

            # Pull out the components of the decrypted text
            #
            l1 = const.SALT_BYTE_LEN
            l2 = l1 + const.HASH_BYTE_LEN
            l3 = l2 + const.DECOUPLED_ID_HEX_LEN

            salt           = text[    : l1 ]
            seqNum_C2D_    = text[ l1 : l2 ]
            decoupled_ID_  = text[ l2 : l3 ]
            req            = text[ l3 :    ]

            # Check that HMAC seq number match matches expected sequence number
            #
            if ( seqNum_C2D_ != seqNum_C2D ):
                print "Error with Sequence Number in HMAC"
                return

            # Check that decoupled_IDs match
            #
            if ( decoupled_ID_ != self.decoupled_ID.encode("hex") ):
                print "Error with Decoupled_IDs"
                return

            # Forward the covert request to the CCP_DP
            #
            if not self.dst_protocol is None:
                self.dst_protocol.transport.write(req)




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
        self.srcFactory.cm_http_callback = None
        self.srcFactory.cm_close_callback = None

        self.srcFactory.ct_dp = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor, srcaddr[1],
                interface=srcaddr[0])
        endpoint.listen(self.srcFactory)
        self.log = logging.getLogger('cb.http_ct_dp')


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
            self.log.debug("HTTP_CT_DP.tunnelMade: Registering Producer 2")
            src_protocol.transport.registerProducer(
                    self.producers[dst_protocol.host], True)

    def tunnelLost(self, src_protocol, dst_protocol):
        """
        Src protocol calls this once it receives a connectionLost,
        We need to remove this tunnel from our structures
        """

        self.log.debug("HTTP_CT_DP.tunnelLost")
        self.tunnels.pop(dst_protocol.host)


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
            self.log.debug("HTTP_CT_DP.setProducer: Registered producer 1")
            self.tunnels[host].src_protocol.transport.registerProducer(producer, True)


    def set_cm_http_callback(self, callback):
        self.srcFactory.cm_http_callback = callback


    def set_cm_close_callback(self, callback):
        self.srcFactory.cm_close_callback = callback




def main():
    log.startLogging(sys.stdout)


    ct_dp = CT_DP(('localhost', 8080), ('localhost', 5002))
    reactor.run()

if __name__ == '__main__':
    main()



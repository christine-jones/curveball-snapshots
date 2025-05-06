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

import base64
import binascii
import copy
import hashlib
import hmac
import os
import random
import re
import sys
import string
import time
import zlib

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.twisted_exit
import cb.util.cb_constants as const
import cb.util.cb_random as cb_random
import cb.util.security_util as security_util
import cb.util.http_util_req as http_util
from cb.mole.encode import HttpMoleEncoder
from cb.mole.c_encode import HttpMoleCryptoEncoder
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor
from twisted.python import log
from M2Crypto import RSA, BIO, EVP
from M2Crypto import RC4
from twisted.internet.task import LoopingCall

use_crypto = False
ccp_port = None
addr = ('10.0.3.16', 80)


class SrcProtocol(Protocol):
    """
    Connecting to Client (e.g., curl, firefox)
    """

    def __init__(self):
        self.dst_p = None

        # We don't use the host or session_key parameters because the
        # only thing we use this encoder for is its digest method, which
        # does not depend on anything except the text.
        #
        self.encoder = HttpMoleCryptoEncoder('fakehost', 'fakekey')
        self.sent_count = 0

    def connectionMade(self):
        self.dst_p = self.factory.dst_p
        self.dst_p.src_p = self

    def connectionLost(self, x):
        self.dst_p.state = const.STATE_1_UNI
        print "srcprotocol: connection lost"

    def dataReceived(self, buf):
        """
        State 3.5:  Ready

        Sending covert data from client in http request
        where buf is plain text
        """
        while buf != '':
            (buf, chunk) = self.extract_chunk(buf)
            req = self.dst_p.send_cipher_req(chunk)
            if buf == '':
                break

    def extract_chunk(self, buf):
        """
        Break covert data into chunks suitable for
        url length constraints
        """

        if len(buf) >= const.HTTPU_MAX_URL_LEN:
            chunk = buf[:const.HTTPU_MAX_URL_LEN]
            buf = buf[const.HTTPU_MAX_URL_LEN:]
        else:
            chunk = buf
            buf = ''

        return (buf, chunk)


class DstProtocol(Protocol):
    """
    Connecting to Decoy destination
    """
    def __init__(self):

        global allocated_sentinel, use_crypto, ccp_port, addr

        self.src_factory = Factory()
        self.src_factory.protocol = SrcProtocol
        self.src_factory.dst_p = self

        self.buf = ''
        self.sentinel_hex = allocated_sentinel
        self.session_key = self.sentinel_hex[const.SENTINEL_HEX_LEN:]
        self.rc4_handshake_c2d = RC4.RC4(self.session_key)
        self.rc4_handshake_d2c = RC4.RC4(self.session_key)
        self.rc4_tunnel = RC4.RC4(self.session_key)

        self.isFirst = True
        self.gotFillerDataCount = 0
        self.send_chaff = LoopingCall( self.sendChaffReq )
        self.total_len = 0
        self.start_time = time.clock()

        self.chaff_recv = 0
        self.chaff_bytes = 0
        self.cov_recv = 0
        self.cov_bytes = 0

        # Note that this is the host name if available, 
        # otherwise the ip address
        #
        self.host_name = addr[0]

        self.state = const.STATE_0_UNI

        self.src_p = None
        self.handshake_ID = None
        self.tunnel_tag = None
        self.tunnel_type = const.HTTP_UNI_TUNNEL

        # We don't use the host or session_key parameters because the
        # only thing we use this encoder for is its digest method, which
        # does not depend on anything except the text.
        #
        self.encoder = HttpMoleCryptoEncoder('fakehost', 'fakekey')

        self.sent_count = 0

    def connectionMade(self):
        """
        State 0:  Request tunnel type

           Cookie :  SESSSIONID=HandshakeID; ID=Tunnel_Tag

        HandshakeID = Sentinel+Nonce_Client
        """

        # Sentinel
        #
        s = const.SENTINEL_DEADBEEF
        if use_crypto == True:
            s = self.sentinel_hex[0:const.SENTINEL_HEX_LEN]

        # Nonce_Client
        #
        self.nonce_client = cb_random.gen_rand_bytes( self,
                const.NONCE_CLIENT_BYTE_LEN)

        # Handshake_ID
        #
        self.handshake_ID = s + self.nonce_client.encode("hex")

        # Tunnel Tag
        #
        self.tunnel_tag = hmac.new(
                const.HTTP_UNI_TUNNEL + self.nonce_client.encode("hex"),
                self.sentinel_hex[const.SENTINEL_HEX_LEN:],
                hashlib.sha256 ).digest()

        # Filler text
        #
        plain_text = const.HTTPU_CLIENTHELLO

        auth_plain_text = '%s%s%s' % (
                self.encoder.digest(plain_text),
                const.HTTPU_HASHSEP,
                plain_text)

        cipher_text = auth_plain_text

        # HTTP Request
        #
        req = http_util.create_http_req(self,
                cipher_text, self.handshake_ID,
                self.tunnel_tag.encode("hex"), self.host_name)

        self.transport.write(req)

        # New state
        #
        self.state = const.STATE_1_UNI

    def sendSentinel(self):
        """
        State 1:  Send sentinel

           Cookie :  SESSSIONID=HandshakeID; ID=Tunnel_Tag

        HandshakeID = Sentinel+Nonce_Client
        """
        self.rc4_handshake_c2d = RC4.RC4(self.session_key)
        self.rc4_handshake_d2c = RC4.RC4(self.session_key)
        self.rc4_tunnel = RC4.RC4(self.session_key)

        # Filler text
        #
        plain_text = const.HTTPU_CLIENTHELLO

        auth_plain_text = '%s%s%s' % (
                self.encoder.digest(plain_text),
                const.HTTPU_HASHSEP,
                plain_text)

        cipher_text = self.rc4_handshake_c2d.update(auth_plain_text)

        # HTTP Request
        #
        req = http_util.create_http_req(self,
                cipher_text, self.handshake_ID,
                self.tunnel_tag.encode("hex"), self.host_name)

        self.transport.write(req)

        # New state
        #
        self.state = const.STATE_3_UNI

    def connectionLost(self, x):

        print "dstprotocol: connection lost"
        if self.src_p:
            self.src_p.transport.loseConnection()

        try:
            reactor.stop()
        except:
            print "HTTP_CT_UNI_CLIENT.connectionLost: reactor already stopped"

    def dataReceived(self, data):
        """
        Data received from DP/Decoy host
        """
        self.buf += data

        while True:

            if self.buf == '' or self.buf == None:
                break

            ( self.buf, resp, payload, unzip_payload, status ) = http_util.extract_http_resp( self.buf, self.tunnel_type )

            if str(status) == '-2':
                print "Response contains connection close"
                self.transport.loseConnection()
                break

            if str(status) == '-3':
                print "Response contains unuseable header type"
                #self.transport.loseConnection()
                break

            if str(status) == '-4':
                break

            if resp is None:
                break

            if self.state == const.STATE_1_UNI:
                self.sendSentinel ( )

            elif self.state == const.STATE_3_UNI:
                self.checkForWelcome ( resp, unzip_payload )

            elif self.state == const.STATE_5_UNI:
                self.ready( resp, unzip_payload )

        if self.state == const.STATE_5_UNI:
            if self.gotFillerDataCount < const.MAX_CHAFF_RESP_RECEIVED:
                self.sendChaffReqForCovertData()

    def sendChaffReq(self):
        """
        Send a chaff-only request.  sendChaffReq() is typically for "small"
        amounts of chaff (when we want to nudge the DP by providing a small
        message) and sendChaffReqForCovertData() is for sending "larger"
        amounts of chaff (when we think that DP has data queued up to send).
        """
        plain_text = const.HTTP_UNI_CHAFF_URL_PATH
        self.send_cipher_req(plain_text)

    def sendChaffReqForCovertData(self):
        """
        See sendChaffReq()
        """
        plain_text = const.HTTP_UNI_CHAFF_COVERT_DATA_URL_PATH
        self.send_cipher_req(plain_text)
        #time.sleep(0.5)

    def send_cipher_req(self, plain_text):
        """
        Create request containing encrypted, integrity checked
        data and send request on to decoy host
        """
        plain_text = str(self.sent_count) + ":" + plain_text

        auth_plain_text = '%s%s%s' % (
                self.encoder.digest(plain_text),
                const.HTTPU_HASHSEP,
                plain_text)

        url_padding = cb_random.gen_rand_bytes( self,
                const.URL_PADDING_BYTE_LEN)

        cipher_text = self.rc4_tunnel.update(auth_plain_text) + url_padding

        req = http_util.create_http_req(self,
                cipher_text, self.handshake_ID,
                self.tunnel_tag.encode("hex"), self.host_name)

        if self.state != const.STATE_0_UNI:
            self.sent_count += 1

        # Send request on to decoy host
        #
        self.transport.write(req)


    def checkForWelcome(self, resp, unzip_payload):
        """
        State 3:  Check for welcome
        """

        # Create mole decoder
        #
        if self.isFirst == True:
            self.isFirst = False
            self.http_mole_encoder = HttpMoleCryptoEncoder(
                    self.host_name, self.sentinel_hex)

            self.send_chaff.start(const.HTTP_SEND_CHAFF_INTERVAL)

        [status, dec_resp, enc_resp
                ] = self.http_mole_encoder.decode_response(resp, commit=True)

        # Because raw response may have zipped payload, we also try
        # unzipped payload
        #
        if status is -1:
            [status, dec_resp, enc_resp
                    ] = self.http_mole_encoder.decode_response(unzip_payload, commit=True)

        if status is -1:
            print 'Error: no DR on path?'
            try:
                reactor.stop()
            except:
                # Eat the exception; we're already shutting down
                return

            return

        if dec_resp != const.HTTPU_CURVEBALLHELLO:
            print 'Error: no welcome string received'
            try:
                reactor.stop()
            except:
                print "HTTP_CT_UNI_CLIENT.dstConnectionFailed: reactor already stopped"

        else:
            self.src_endpoint = endpoints.TCP4ServerEndpoint(
                    reactor, ccp_port)
            self.src_endpoint.listen(self.src_factory)

            # Transition to state 5, and prime the pump with chaff
            self.state = const.STATE_5_UNI
            self.sendChaffReqForCovertData()

    def ready(self, resp, unzip_payload):
        """
        State 5:  Ready

        Receiving covert data from DP, conveying covert
        data to Client
        """

        # Create mole decoder
        #
        if self.isFirst == True:
            self.isFirst = False
            self.http_mole_encoder = HttpMoleCryptoEncoder(
                    self.host_name, self.sentinel_hex)

            self.send_chaff.start(const.HTTP_SEND_CHAFF_INTERVAL)

        [status, dec_resp, enc_resp
                ] = self.http_mole_encoder.decode_response(resp, commit=True)

        # Because raw response may have zipped payload, we also try
        # unzipped payload
        #
        if status is -1:
            [status, dec_payload, enc_resp
                    ] = self.http_mole_encoder.decode_response(
                            unzip_payload, commit=True)

        if status is -1:
            try:
                reactor.stop()
            except:
                print "HTTP_CT_UNI_CLIENT.dstConnectionFailed: reactor already stopped"

        # Forward response up to Client-side CCP
        #
        len_resp = len(str(resp))
        len_dec_resp = len(str(dec_resp))
        if len_dec_resp > 0:
            self.src_p.transport.write( dec_resp )
            self.gotFillerDataCount = 0
            self.cov_recv += 1
            self.cov_bytes += len_resp
        else:
            self.gotFillerDataCount += 1
            self.chaff_recv += 1
            self.chaff_bytes += len_resp

        # Uncomment if you want to see stats of how many
        # chaff msgs there have been, etc
        #
        # if self.chaff_recv % 100 == 0:
        #     print "%s %s %s %s" % (self.chaff_recv,
        #                            self.chaff_bytes,
        #                            self.cov_recv,
        #                            self.cov_bytes)

class HTTPCTUniClient(object):
    """
    Client side of CT
    """

    def __init__(self, addr_, ccp_port_, use_crypto_, allocated_sentinel_):

        global use_crypto, ccp_port, addr, allocated_sentinel

        ccp_port = ccp_port_
        addr = addr_

        # TODO: check that the allocated sentinel is not bogus.
        use_crypto = use_crypto_
        allocated_sentinel = allocated_sentinel_

        # Connecting to decoy destination
        #
        dst_factory = Factory()
        dst_factory.protocol = DstProtocol
        dst_endpoint = endpoints.TCP4ClientEndpoint(reactor, addr[0], addr[1])
        self.http_tunnel = dst_endpoint.connect(dst_factory)
        self.http_tunnel.addErrback(self.dstConnectionFailed)

    def dstConnectionFailed(self, reason):

        print str(reason.value)
        self.http_tunnel.cancel()

        cb.util.twisted_exit.EXIT_STATUS = 1

        try:
            reactor.stop()
        except:
            print "HTTP_CT_UNI_CLIENT.dstConnectionFailed: reactor already stopped"

def main():
    global use_crypto, ccp_port

    addr1 = ('10.0.3.16', 80)

    ccp_port = 4435
    use_crypto = True

    log.startLogging(sys.stdout)
    http_ct = HTTPCTClient(addr1, ccp_port, use_crypto)
    reactor.run()

if __name__ == '__main__':
    main()


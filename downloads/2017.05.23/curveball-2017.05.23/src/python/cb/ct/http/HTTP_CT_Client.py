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
import hashlib
import hmac
import os
import random
import re
import string
import sys
import time
import zlib

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.twisted_exit
import cb.util.cb_constants as const
import cb.util.cb_random as cb_random
import cb.util.security_util as security_util
import cb.util.http_util_req as http_util
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor
from twisted.python import log
from M2Crypto import RSA, BIO, EVP

use_crypto = False
ccp_port = None
addr = ('10.0.3.16', 80)


class SrcProtocol(Protocol):
    """
    Connecting to Client
    """

    def __init__(self):
        self.dst_p = None
        self.host_name = None

    def connectionMade(self):
        self.dst_p = self.factory.dst_p
        self.dst_p.state = const.STATE_7
        self.dst_p.src_p = self
        self.host_name = self.factory.host_name

    def connectionLost(self, x):
        self.dst_p.state = const.STATE_1

    def dataReceived(self, data):
        """
        State 5.5:  Ready

          A.     URL :  SeqNum_C2D +
          B.            HMAC_Client( R2 ) +
          C.            E_Client( R2 )

          D.  Cookie :  SESSSIONID=Decoupled_ID

         R2 =  Salt_3        +
               SeqNum_C2D    +
               Decoupled_ID  +
               CovertData

        Sending covert data from client in http request
        """

        # A.  SeqNum_C2D
        #
        self.dst_p.seqNum_C2D_Counter = self.dst_p.seqNum_C2D_Counter + 1

        s = ( self.dst_p.seqNum_C2D_Rand +
              str( self.dst_p.seqNum_C2D_Counter ) )

        seqNum_C2D = hmac.new(
            s, self.dst_p.client_hash, hashlib.sha256 ).digest()

        # B.  HMAC_Client( R2 )
        #
        salt_3 = cb_random.gen_rand_bytes(self, const.SALT_BYTE_LEN)

        text = ( salt_3 +
                 seqNum_C2D +
                 self.dst_p.decoupled_ID +
                 data )

        auth_text = hmac.new(
            text, self.dst_p.client_hash, hashlib.sha256 ).digest()

        # C.  E_Client( R2 )
        #
        enc_text = security_util.encrypt_text(self,
            text, self.dst_p.client_key, True, False, False)

        # D.  SESSSIONID=Decoupled_ID
        #
        final_text = seqNum_C2D + auth_text + enc_text

        req = http_util.create_http_req(self,
            final_text, self.dst_p.decoupled_ID,
            self.dst_p.tunnel_tag.encode("hex"),
            self.host_name)

        # Send request on to decoy host
        #
        self.dst_p.transport.write(req)





class DstProtocol(Protocol):
    """
    Connecting to Decoy destination
    """

    def __init__(self):


        global allocated_sentinel
        global use_crypto, ccp_port

        # Note that this is the host name if available,
        # otherwise the ip address
        #
        self.host_name = addr[0]

        self.src_factory = Factory()
        self.src_factory.protocol = SrcProtocol
        self.src_factory.dst_p = self
        self.src_factory.host_name = self.host_name
        self.buf = ''

        self.state = const.STATE_0
        self.src_p = None

        self.extra_d2c_key = None

        self.client_key  = None
        self.dp_key      = None
        self.client_hash = None
        self.dp_hash     = None

        self.decoupled_ID = None
        self.tunnel_tag = None
        self.tunnel_type = const.HTTP_BI_TUNNEL

        self.seqNum_D2C_Rand = None
        self.seqNum_C2D_Rand = 0
        self.seqNum_D2C_Counter = 0
        self.seqNum_C2D_Counter = 0

        self.nonce_client = None
        self.nonce_dp = None
        self.premaster = None
        self.handshake_ID = None
        self.sentinel_hex = allocated_sentinel

        [self.extra_d2c_key] = security_util.obtain_extra_keys(
            self, self.sentinel_hex)

        self.pubkey_dp = security_util.obtain_pubkey_dp( self )

        self.seqNum_C2D_Rand = cb_random.gen_rand_bytes(
            self, const.SEQ_NUM_RAND_BYTE_LEN)

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
        self.nonce_client = cb_random.gen_rand_bytes(self,
            const.NONCE_CLIENT_BYTE_LEN)

        # Handshake_ID
        #
        self.handshake_ID = ( s + self.nonce_client.encode("hex") )

        # Tunnel_Tag
        #
        self.tunnel_tag = hmac.new(
                const.HTTP_BI_TUNNEL + self.nonce_client.encode("hex"),
                self.sentinel_hex[const.SENTINEL_HEX_LEN:],
                hashlib.sha256 ).digest()

        # HTTP Request
        #
        rand_url_len = random.randint(10, 40)
        rand_url = cb_random.gen_rand_bytes(self, rand_url_len)
        req = http_util.create_http_req(self,
                rand_url, self.handshake_ID, self.tunnel_tag.encode("hex"),
                self.host_name)
        self.transport.write(req)

        # New state
        #
        self.state = const.STATE_1

    def sendSentinel(self):
        """
        State 1:  Send sentinel

           Cookie :  SESSSIONID=HandshakeID; ID=Tunnel_Tag

        HandshakeID = Sentinel+Nonce_Client
        """
        # HTTP Request
        #
        req = http_util.create_http_req(self,
            '', self.handshake_ID, self.tunnel_tag.encode("hex"),
            self.host_name)
        self.transport.write(req)

        # New state
        #
        self.state = const.STATE_3

    def connectionLost(self, x):

        if self.src_p:
            self.src_p.transport.loseConnection()

        try:
            reactor.stop()
        except:
            print "HTTP_CT_CLIENT.connectionLost: reactor already stopped"

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

            if resp is None:
                break

            # We don't care whether the first response (which is received in
            # STATE_1) is not 200, but we do care whether all subsequent
            # responses are not 200. The first request/response are simply
            # for determining the tunnel type, and so the response will not
            # be rewritten. Because the first request contains a GET /RandomURL,
            # it is very likely that the resulting request will not be 200
            #
            if str(status) != "200" and self.state != const.STATE_1:
                print "Not in tunnel_type state and response status is not 200: %s" % str(status)
                self.transport.loseConnection()
                break

            if self.state == const.STATE_1:
                self.sendSentinel()

            elif self.state == const.STATE_3:
                self.sendPremaster( resp )

            elif self.state == const.STATE_5:
                self.checkForWelcome ( resp )

            elif self.state == const.STATE_7:
                self.ready( payload )

            else:
                self.transport.loseConnection()
                break


    def sendPremaster(self, resp):
        """
        State 3:  Send premaster

         A.     URL :   E_KeyDPPub( Premaster )       +
                                    SeqNum_C2D_Rand ) +

         B.          HMAC_KeyDPPub( Premaster         +
                                    SeqNum_C2D_Rand   +
                                    Decoupled_ID      +
                                    Nonce_DP )

         C.  Cookie :  SESSSIONID=Decoupled_ID

        Decoupled_ID = Randomstring
        """
        try:

            # Check that DP sent back a decoupled_ID in a cookie
            #
            [new_cookie, self.decoupled_ID] = self.get_cookie_val( resp )
            if self.decoupled_ID == -1:
                self.transport.loseConnection() # TODO: CHECK!
                return

            # Pull out the covert message and extract its components
            #
            pieces = resp.split('\r\n\r\n', 1)
            if len(pieces) != 2:
                print 'ERROR: bogus http response (%d pieces)' % len(pieces)
                self.transport.loseConnection() # TODO: CHECK!
                return

            # TODO: what does an ordinary client do when it gets BOTH
            # a "content-length" and "transfer-encoding chunked"?
            # We don't detect this, but just believe the first.
            #
            match_len = False
            match_chunk = False
            header = pieces[0]
            for line in header.split('\r\n'):
                match_len = re.search(
                        '^[Cc]ontent-[Ll]ength:\s*([0-9]+)\s*$', line)
                if match_len:
                    # print 'XXXXXX content-length' # TODO: rm
                    break
                match_chunk = re.search(
                        '^[Tt]ransfer-[Ee]ncoding:\s*chunked\s*$', line)
                if match_chunk:
                    # print 'XXXXXX chunk-encoding' # TODO: rm
                    break

            if match_len:
                covert_begin  = str(resp).index(const.END_HEADER) + len(const.END_HEADER)
                covert_end = ( const.SIGNATURE_DP_PRIV_KEY_BYTE_LEN +
                               const.ENCRYPT_SALT_NONCE_BYTE_LEN )
                covert = resp[ covert_begin : covert_begin + covert_end ]

            elif match_chunk:
                chunk_len_begin  = str(resp).index(const.END_HEADER) + len(const.END_HEADER)
                chunk_len_to_end = str(resp[chunk_len_begin:])
                chunk_len_end    = chunk_len_to_end.index(const.END_LINE) + len(const.END_LINE)
                chunk_len        = chunk_len_to_end[ : chunk_len_end ]

                covert_begin = len(chunk_len) + str(resp).index(const.END_HEADER) + len(const.END_HEADER)
                covert_end = const.SIGNATURE_DP_PRIV_KEY_HEX_LEN + const.ENCRYPT_SALT_NONCE_HEX_LEN
                covert = str( resp[ covert_begin : covert_begin + covert_end ] )


                if not all(c in string.hexdigits for c in covert):
                    print "covert msg is not hex, not a hijack"
                    self.transport.loseConnection() # TODO: CHECK!
                    return
                else:
                    covert = covert.decode("hex")
            else:
                print 'ERROR: no Content-Length or "Transfer-Encoding chunked"'
                self.transport.loseConnection() # TODO: CHECK!
                return

            i1 = const.SIGNATURE_DP_PRIV_KEY_BYTE_LEN
            signature    = covert[ : i1 ]
            enc_nonce_dp = covert[ i1 : ]

            dec_nonce_dp = security_util.decrypt_text(self,
                enc_nonce_dp, self.extra_d2c_key, False, True, False)

            if dec_nonce_dp == -1:
                self.transport.loseConnection() # TODO: CHECK!
                return

            salt_1        = dec_nonce_dp[ : const.SALT_BYTE_LEN ]
            self.nonce_dp = dec_nonce_dp[ const.SALT_BYTE_LEN : ]

            # Verify that signature matches str_to_verify
            #
            str_to_verify = (
                    salt_1 + self.nonce_dp + new_cookie + self.handshake_ID )

            verified = security_util.verify_signature( self,
                self.pubkey_dp, str_to_verify, signature )


            if verified == True:

                # A. E_KeyDPPub( Premaster + SeqNum_C2D_Rand )
                #
                premaster = cb_random.gen_rand_bytes( self,
                    const.PREMASTER_BYTE_LEN )

                k = RSA.load_pub_key_bio( BIO.MemoryBuffer(self.pubkey_dp) )

                enc_text = k.public_encrypt(
                    premaster + self.seqNum_C2D_Rand,
                    RSA.pkcs1_oaep_padding )

                # B. HMAC_KeyDPPub( Premaster + SeqNum_C2D_Rand + Decoupled_ID + Nonce_DP )
                #
                # Note that decoupled_ID that is decoded here is client's
                # decouple_ID: it just happens to be stored in hex.
                # If something gets messed up, should fall through to
                # TypeError in except
                #
                text = ( premaster +
                         self.seqNum_C2D_Rand +
                         self.decoupled_ID.decode("hex") +
                         self.nonce_dp )

                auth_text = hmac.new( text, self.pubkey_dp, hashlib.sha256 ).digest()
                bin_text = binascii.hexlify( enc_text + auth_text )
                zip_text = zlib.compress( bin_text )

                # C. SESSSIONID=Decoupled_ID
                #
                req = http_util.create_http_req(self,
                    zip_text, self.decoupled_ID, self.tunnel_tag.encode("hex"),
                    self.host_name )

                self.transport.write(req)

                [ self.client_key,
                  self.dp_key,
                  self.client_hash,
                  self.dp_hash ] = security_util.compute_keys(
                     self, premaster, self.nonce_client, self.nonce_dp )

                # New state
                #
                self.state = const.STATE_5
            else:
                self.transport.loseConnection() # TODO: CHECK!

        except ValueError, TypeError:
            print 'Error: message has no payload'
            self.transport.loseConnection()


    def checkForWelcome(self, resp):
        """
        State 5:  Check for welcome
        """
        try:

            # Separate out HMAC from encrypted text
            #
            header_end = str(resp).index(const.END_HEADER)
            auth_enc_text = resp[ header_end + len(const.END_HEADER) : ]
            auth_text = auth_enc_text[ : const.HASH_BYTE_LEN ]
            enc_text = auth_enc_text[ const.HASH_BYTE_LEN : ]

            # Check for welcome to curveball
            #
            text = security_util.decrypt_text(self,
                enc_text, self.dp_key, False, True, False)

            if text == -1:
                self.transport.loseConnection()
                return
            i1 = const.SALT_BYTE_LEN
            i2 = i1 + const.SEQ_NUM_RAND_BYTE_LEN

            salt_2                      = text[    : i1 ]
            self.seqNum_D2C_Rand = text[ i1 : i2 ]
            welcome_str                 = text[ i2 :    ]

            str(text).index('welcome to curveball')

            # Check that HMAC is correct
            #
            auth_text_ = hmac.new( text, self.dp_hash, hashlib.sha256 ).digest()
            if auth_text != auth_text_:
                self.transport.loseConnection() # TODO: CHECK!
                return

            # If HMAC is correct, start listening for covert requests
            # from Client-side CCP
            #
            self.src_endpoint = endpoints.TCP4ServerEndpoint(reactor, ccp_port)
            self.src_endpoint.listen(self.src_factory)


        except ValueError:
            print 'Error: no welcome string received'
            self.transport.loseConnection()




    def get_cookie_val(self, data):
        """
        Don't want to always be using sentinel as a cookie,

        DP will send back a new cookie to use instead, using Set-Cookie
        So Client must extract new cookie value from Set-Cookie field
        """

        try:
            cookie_begin = data.index('Set-Cookie: ')
            cookie_end = cookie_begin + \
                         data[cookie_begin:].index(const.END_LINE) + \
                         len(const.END_LINE)
            cookie = data[cookie_begin : cookie_end]
            cookie_offset = cookie_begin + len('Set-Cookie: ')

            cookie_temp = data[ cookie_offset : cookie_end - len(const.END_LINE) ]
            is_equals = str(cookie_temp).index("=")
            is_semicolon = str(cookie_temp).index(";")
            cookie_val = str(cookie_temp)[is_equals + 1: is_semicolon]

            return [cookie, cookie_val]

        except ValueError:
            self.transport.loseConnection()
            return [-1, -1]


    def ready(self, payload):
        """
        State 7:  Ready

            Receiving covert data from DP, conveying covert
            data to Client
        """

        # Separate out seq number, HMAC, and encrypted text
        #
        auth_enc_text = payload

        l1 = const.HASH_BYTE_LEN
        l2 = l1 + const.HASH_BYTE_LEN

        seqNum_D2C = auth_enc_text[    : l1 ]
        auth_text  = auth_enc_text[ l1 : l2 ]
        enc_text   = auth_enc_text[ l2 :    ]

        # Check that seq number tag on pkt matches expected seq number
        #
        self.seqNum_D2C_Counter = self.seqNum_D2C_Counter + 1
        s = self.seqNum_D2C_Rand + str( self.seqNum_D2C_Counter )
        seqNum_D2C__ = hmac.new(
        s, self.dp_hash, hashlib.sha256 ).digest()

        if ( seqNum_D2C__ != seqNum_D2C ):
            self.seqNum_D2C_Counter = self.seqNum_D2C_Counter - 1
            print "Error with Sequence Number tag on packet"
            self.transport.loseConnection()
            return

        # Decrypt text
        #
        text = security_util.decrypt_text(self, enc_text,
            self.dp_key, False, True, False)

        if text == -1:
            self.transport.loseConnection() # TODO: CHECK!
            return

        # Check that HMAC is correct
        #
        auth_text_ = hmac.new(
            text, self.dp_hash, hashlib.sha256 ).digest()

        if ( auth_text_ != auth_text ):
            print "Error with hmac"
            self.transport.loseConnection()
            return

        # Pull out the components of the decrypted text
        #
        l1 = const.SALT_BYTE_LEN
        l2 = l1 + const.HASH_BYTE_LEN

        salt_4      = text[    : l1 ]
        seqNum_D2C_ = text[ l1 : l2 ]
        resp        = text[ l2 :    ]

        # Check that HMAC seq number match matches expected sequence number
        #
        if ( seqNum_D2C_ != seqNum_D2C ):
            print "Error with Sequence Number in HMAC"
            self.transport.loseConnection()
            return

        # Forward response up to Client-side CCP
        #
        self.src_p.transport.write( resp )




class HTTPCTClient(object):
    """
    Client side of CT
    """
    def __init__(self, addr_, ccp_port_, use_crypto_, allocated_sentinel_):

        global use_crypto, ccp_port, addr, allocated_sentinel

        ccp_port = ccp_port_
        addr = addr_

        # TODO: check that the allocated sentinel is not bogus.
        #
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
            print "HTTP_CT_CLIENT.dstConnectionFailed: reactor already stopped"

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


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
Server end of the TLS covert channel

Connects to the Server_Stub

Listens for a connection from the CT_Client, when one arrives,
it plumbs the two together.  

Implements the key setup and exchange done between the DP and the Client in
order to hijack the TLS session after the TCP connection has been hijacked.

Uses the cb.cssl.cssl implementation of TLS data records, so the range of
expression is limited; only certain ciphers are supported.

The protocol for setting up the new session keys for the communication between
the Client and the DP is as follows:

In the symmetric case:

0. The DP verifies that the DH responds with a CHANGE_CIPHER_SPEC
message to the client.  This assures us that the DH is happy with this
instance of the client, and protects us from being spoofed by a
doppelganger. 

1. The Client sends a TLS application record to the DH.  The DP can't decode this
record (because it doesn't know the key established between the Client and the
DH) so it throws this record away and executes the rest of the protocol.
DP state is 'start'.

--- The above is done by the TLSFlowMonitor class. Once the client
    sends an application data record, the connection is hijacked, and
    this part of the program runs

2. The DP sends a 'curveball hello' TLS data record to the Client.  This data
record does NOT use the same ciphersuite or keys as the original C<->DD
connection.  The curveball hello message consists of the random field that the
client sent originally (in its TLS hello message) signed by the Curveball
private key and wrapped in a TLS application data record using the ??? key.
DP state is 'hello'.

When the Client sees the 'curveball hello', it either dies (if it's not running
curveball and this was a false alarm) or else it answers with a session key that
it chooses.

4.  The DP receives data records from the Client until it sees the message
containing the session key.  When the DP sees this key, it switches to use this
key for all later communication on with the Client.  All subsequent TLS records
from the Client are decrypted with this key, checked, and then passed to CCP.
DP state is 'keyed'.

If the Client message to the DD is too long to fit into a single record, then
the first data record might be followed by a number of records before the
response from the Client to the 'curveball hello'.  All of these records are
discarded and no response is generated.  If the client does not respond with a
session key message within a fixed period of time, the session is declared
invalid and closed.

"""

import binascii
import logging
import socket
import struct
import random
# import M2Crypto
import array

import datetime
import hashlib
import hmac
import sys
import os

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from zope.interface import implements
from twisted.internet import interfaces
from twisted.internet import reactor

# import cb.cssl.aes
# import cb.cssl.cssl
# import cb.cssl.rsa
import cb.cssl
import cb.cssl.cssl
import cb.util.cblogging
import cb.bp
import exceptions

# enables debug messages
# the construct
# DEBUG and debug(msg)
# is a case of over-optimization --- the test whether the message
# should be printed is done before the function call happens, saving
# the cost of the function call

# FIXME
# often one wants to replace DEBUG and debug(...) with self.log.debug(...)
import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))
def log_debug(msg):
    print >> sys.stderr, "CT_DP2: %s" % msg

# FIXME
# and replace DEBUG and warn with self.log.warn
def log_warn(msg):
    log_debug(msg)

# FIXME
# and replace log_error with self.log.warn
def log_error(msg):
    print >> sys.stderr, "CT_DP2: %s" % msg

def debug_logger(log):
    if DEBUG:
        log.setLevel(logging.DEBUG)
        print >> sys.stderr, "Trying to set up debug logging to console"
        
        # this is from the logging cookbook:
        # http://docs.python.org/howto/logging-cookbook.html#logging-cookbook
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(name)-12s: $(levelname)-8s %(message)s')
        console.setFormatter(formatter)
        log.addHandler(console)

class DstProtocol(Protocol):
    """
    CT_DP <-> CCP_DP protocol
    """

    def __init__(self):
        self.log = logging.getLogger('cb.ct.tls')
        self.cc = None
        self.recv_buf = ''

    def connectionMade(self):
        DEBUG and log_debug('CT_DP2.DstProtocol: connectionMade')
        self.cc = self.factory.src_protocol

    def connectionLost(self, reason):
        """ 
        We've lost our connection to the dst (CCP_DP)
        for some reason, close to the connection to the client
        as well
        """
        DEBUG and log_debug('CT_DP2.DstProtocol: connectionLost')
        self.cc.transport.loseConnection()


    # FIXME? handle_error(self)
    # FIXME? handle_close(self)

    def dataReceived(self, new_data):
        """
        Read data that is being passed from CCP toward the client, via CT.
        """
        DEBUG and log_debug('%d bytes of new data' % len(new_data))

        self.recv_buf += new_data
        # TODO: error check
        if self.cc:
            self.cc.ccdp_to_cc(self.recv_buf)
            self.recv_buf = ''
        else:
            # FIXME: very strange situation.  We should not be getting anything
            # from CCP until we are connected.  (the first thing that CCP sends
            # should be a response to something the client did)
            #
            log_warn('got data from ccp before ct connection?')


class SrcProtocol(Protocol):
    """
    Accepted connection from the client (via the TCP engine) to the DP side of
    the CT.
    """

    def cryptostart(self):

        DEBUG and log_debug("cryptostart -----------------------------------------------")

        session_key = self.TLSflow.crypto.serverKeyBlock
        iv = self.TLSflow.crypto.serverIVBlock
        mac_key = self.TLSflow.crypto.serverMACBlock
        
        DEBUG and log_debug("to-client session_key: %s; iv: %s; mac_key: %s"
                            % (binascii.hexlify(session_key),
                               binascii.hexlify(iv),
                               binascii.hexlify(mac_key)))

        self._to_client = cb.cssl.cssl.CurveballTLS()
        self._to_client.cipher_set(
            self.TLSflow.crypto.createCipherFunc(session_key, iv), iv)

        self._to_client.hmac_key_set(mac_key)
        self._to_client.sequence_number_set(1)

        session_key = self.TLSflow.crypto.clientKeyBlock
        iv = self.TLSflow.crypto.clientIVBlock
        mac_key = self.TLSflow.crypto.clientMACBlock
        self._from_client = cb.cssl.cssl.CurveballTLS()

        DEBUG and log_debug("from-client session_key: %s; iv: %s; mac_key: %s"
                            % (binascii.hexlify(session_key),
                               binascii.hexlify(iv),
                               binascii.hexlify(mac_key)))

        self._from_client.cipher_set(
            self.TLSflow.crypto.createCipherFunc(session_key, iv), iv)

        self._from_client.hmac_key_set(mac_key)
        # the first two messages from the client were digested by the
        # connection_monitor  
        self._from_client.sequence_number_set(3)

        records = self._to_client.create_data_records('welcome to curveball\0')

        DEBUG and log_debug("cyphertext: [%s]"
                            % (' '.join([binascii.hexlify(x) for x in records])))
        DEBUG and log_debug("Sending welcome to curveball"
                            + "-----------------------------------------------")

        self.transport.write(''.join(records))

    def connectionMade(self):
        """
        TLSFlowMonitor has stepped through the Curveball handshake.  
        Use the callback to get a handle for the TLSFlowMonitor, which
        knows the session key for the connection.
        """

        p = self.transport.getPeer()
        DEBUG and log_debug('CT_DP2.SrcProtocol: connectionMade (%s, %s)'
                            % (str(p.host), str(p.port)))

        self.TLSflow = self.factory.cm_callback((p.host, p.port))

        dstFactory = Factory()
        dstFactory.protocol = DstProtocol
        dstFactory.src_protocol = self

        endpoint = endpoints.TCP4ClientEndpoint(reactor,
                                                self.factory.dstaddr[0],
                                                self.factory.dstaddr[1])
        d = endpoint.connect(dstFactory)
        d.addCallback(self.dstConnected)
        self.cryptostart()

    def connectionLost(self, reason):
        """ 
        We've lost the connection to the src (client), shut down
        the connection to the dst (CCP_DP).
        """
        DEBUG and log_debug('CT_DP2.SrcProtocol: connectionLost')
        if not self.dst_protocol is None:
            self.dst_protocol.transport.loseConnection()
            self.factory.ct_dp.tunnelLost(self, self.dst_protocol)

        p = self.transport.getPeer()      
        self.factory.cm_close_callback((p.host, p.port))

    def dstConnected(self, protocol):
        DEBUG and log_debug('CT_DP2.SrcProtocol: dstConnected')
        self.dst_protocol = protocol
        self.factory.ct_dp.tunnelMade(self, self.dst_protocol)

    def __init__(self):

        exe_dir = os.path.normpath(
                os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))

        pubkeys = [
                os.path.join(exe_dir, '..',
                        'auth', 'certs', 'pub.pem'),
                os.path.join(exe_dir, '..', '..',
                        'build', 'auth', 'certs', 'pub.pem'),
                   ]
        privkeys = [
                os.path.join(exe_dir, '..',
                        'auth', 'certs', 'priv.pem'),
                os.path.join(exe_dir, '..', '..',
                        'build', 'auth', 'certs', 'priv.pem'),
                   ]

        rsa_pubkey_fname = None
        rsa_privkey_fname = None

        for f in pubkeys:
            if os.path.exists(f):
                rsa_pubkey_fname = f
                break
        if rsa_pubkey_fname == None:
            raise exceptions.IOError("Can't find pub keyfile among %s" % str(pubkeys))
            
        for f in privkeys:
            if os.path.exists(f):
                rsa_privkey_fname = f
                break
        if rsa_privkey_fname == None:
            raise exceptions.IOError("Can't find private keyfile among %s" % str(privkeys))

        rsa_passphrase = ''

        self.log = logging.getLogger('cb.ct.tls')
        debug_logger(self.log)

        self.dstFactory = None
        self.dst_protocol = None # DstProtocol instance 
        self.toServer = ''
        self.recv_buf = ''

        self._to_client = cb.cssl.cssl.CurveballTLS()
        self._from_client = cb.cssl.cssl.CurveballTLS()

    def dataReceived(self, data):
        DEBUG and log_debug('%d bytes dataReceived' % len(data))
        self.state_machine_input(data)

    def ccdp_to_cc(self, buf):
        """
        Wrap a buffer in TLS records and send them on their way to the client.
        """
        # DEBUG and log_debug('ccdp_to_cc...')
        records = self._to_client.create_data_records(buf)

        # Using dispatcher_with_send; don't check for partial send.
        try:
            self.transport.write(''.join(records))
        except socket.error, why:
            # TODO: Need to close down this dispatcher
            DEBUG and log_debug('CT_DP2.SrcProtocol.ccdp_to_cc: socket error: %s'
                           % str(why))
            pass

    # end def

    # the "state machine" part of the name is vestigal --- once upon a
    # time, this class played a role in the handshake (it may do so,
    # once again)
    def state_machine_input(self, buf):
        DEBUG and log_debug("CT2 Received data")
        self.recv_buf += buf
        if self.dst_protocol == None:
            DEBUG and log_debug("state machine received data before dst_protocol ready")
            return


        while True:
            # FIXME: tlslitify this
            start = cb.cssl.cssl.CurveballTLS.find_record_start(self.recv_buf)
            DEBUG and log_debug("state machine: record start: %d" % start)
            if start < 0:
                return 
            else:
                if start != 0:
                    log_warn("CT_DP2.SrcProtocol.state_machine_input: "
                                   + "Why is a record not appearing at byte 0?")
                    self.recv_buf = self.recv_buf[start:]

            # Need to figure out if we have a complete record.
            # If so, then we need to consume it (if it it's broken).
            #
            result = self._from_client.get_next_data_record(self.recv_buf,
                                                            check_hmac=False,
                                                            check_pad=False,
                                                            do_decrypt=False,
                                                            check_len=False)
            if not result:
                DEBUG and log_debug("incomplete record or other problem")
                return False
            else:
                (_buf, reclen) = result

            DEBUG and log_debug("process data record (len %d)" % reclen)

            try:
                result = self._from_client.get_next_data_record(self.recv_buf,
                                                                check_hmac=True,
                                                                check_pad=True,
                                                                do_decrypt=True,
                                                                check_len=True)
            except cb.cssl.cssl.HMacError:
                # hmac check failed, time to flee!
                self.transport.lose_connection()
                
            if not result:
                log_error("CT_DP2.SrcProtocol.state_machine_input: "
                          + "No result after get_next_data_record")
                return
            else:
                (data, consumed) = result
                self.recv_buf = self.recv_buf[consumed:]
                # check return code
                #
                self.dst_protocol.transport.write(data)


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
        self.srcFactory.cm_callback = None
        self.srcFactory.cm_close_callback = None
        self.srcFactory.ct_dp = self

        endpoint = endpoints.TCP4ServerEndpoint(reactor, srcaddr[1], interface=srcaddr[0])
        endpoint.listen(self.srcFactory)
        self.log = logging.getLogger('cb.ct_dp')
        debug_logger(self.log)

    def tunnelMade(self, src_protocol, dst_protocol):
        """
        The SRC protocol calls this once it has received a connection
        and connect it to a DST flow.
        """
        # Store the host since it goes away before connectionLost is called

        DEBUG and log_debug("CT_DP2.tunnelMade")
        dst_protocol.host = str(dst_protocol.transport.getHost())

        self.tunnels[dst_protocol.host] = (src_protocol, dst_protocol)

        # We call this here in case setProducer was called before 
        # we entered this function
        if dst_protocol.host in self.producers:
            DEBUG and log_debug("CT_DP2.tunnelMade: Registering Producer 2")
            src_protocol.transport.registerProducer(self.producers[dst_protocol.host],
                                                    True)

    def tunnelLost(self, src_protocol, dst_protocol):
        """
        The SRC protocol calls this once it receives a connectionLost,
        we need to remove this tunnel from our structures
        """
        DEBUG and log_debug("CT_DP2.tunnelLost")
        self.tunnels.pop(dst_protocol.host)

    def getTunnel(self, host):
        if not host in self.tunnels:
            return None
        return self.tunnels[host]

    def setProducer(self, host, producer):
        DEBUG and log_debug('CT_DP.setProducer %s' % str(host))
        host = str(host)
        if not host in self.tunnels:
            return
        
        self.producers[host] = producer

        # We call this here as well as tunnelMade, as we don't know
        # which event will occur first
        if host in self.tunnels:
            DEBUG and log_debug("CT_DP2.setProducer: Registered producer 1")
            self.tunnels[host].src_protocol.transport.registerProducer(producer, True)

    def set_cm_callback(self, callback):
        self.srcFactory.cm_callback = callback

    def set_cm_close_callback(self, callback):
        self.srcFactory.cm_close_callback = callback


if __name__ == '__main__':
    ct_dp = CT_DP(('localhost', 5001), ('localhost', 5002))

    reactor.run()



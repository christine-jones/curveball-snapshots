#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017 and in
# part by a grant from the United States Department of State.
# The opinions, findings, and conclusions stated herein are those
# of the authors and do not necessarily reflect those of the United
# States Department of State.
#
# Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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
import copy
import dpkt
import hashlib
import hmac
import logging
import os
import re
import socket
import struct
import sys
import time
import traceback
import zlib

from tlslite.utils.codec import Parser as tlsParser
import tlslite.messages as tlsTm
import tlslite.utils.codec as tlsTc
import tlslite.utils.compat as tlsCompat
import tlslite.utils.cryptomath
from tlslite.utils.cipherfactory import createAES, createRC4, createTripleDES
import tlslite.constants as tlsConst
import tlslite.mathtls as tlsMath
import tlslite.HandshakeSettings
from tlslite.utils import hmac as tlsHmac
from tlslite.X509CertChain import X509CertChain as tlsX509Chain
from tlslite.messages import Certificate as tlsCertificate
from tlslite.messages import Finished as tlsFinished
from twisted.internet import reactor

import cb.bp
import cb.util.flow
import cb.util.cb_constants as const
import cb.util.cb_constants_dp as const_dp
import cb.util.cb_random as cb_random
from cb.mole.mole import MoleTunnelDp, TLSMoleTunnelDp
from cb.mole.c_encode import HttpMoleCryptoEncoder
import cb.util.security_util as security_util
import cb.util.privkey_util as privkey_util
import cb.util.http_util_req as http_util
from cb.util.packet import Packet
from cb.tcphijack.tcphijack import TCPHijack, HijackManager
import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cblogging
from cb.util.nstencil import EncryptedStencilDecoder

from M2Crypto import RC4, EVP

DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))

permit_deadbeef = False

# FIXME -- replace DEBUG and log_debug(...) with self.log.debug(...)
def log_debug(msg):
    print >> sys.stderr, 'connection_monitor: %s' % msg

# FIXME -- replace log_warn with self.log.warning
def log_warn(msg):
    print >> sys.stderr, 'connection_monitor(warning): %s' % msg

# FIXME -- replace log_info with self.log.info
def log_info(msg):
    print >> sys.stderr, 'connection_monitor(info): %s' % msg

# FIXME -- replace log_error with self.log.info
def log_error(msg):
    print >> sys.stderr, 'connection_monitor(ERROR): %s' % msg

"""
The flow of packets at the hijack/handshake level in the DP is the following:

DR2DP_DP <-> ConnectionMonitor <-> FlowMonitor <-> TCPHijack <-> HijackManager <-> TUN_Dev -> CT_DP

"""


def ppbytes(bytes):
    """
    Takes a byte array and returns a string formatting it byte by byte
    in a form that might be helpful in figuring out where protocol
    elements are, in order to debug bytestream synchronization
    problems.
    """
    retval = ""
    for i in range(0, len(bytes)):
        retval += ("%03d(0x%02x)" % (int(bytes[i]), int(bytes[i])))
        # print separator or newline
        if (((i+1) % 8) == 0) or (i+1 == len(bytes)):
            retval += "\n"
        elif ((i + 1) % 4) == 0:
            retval += " | "
        else:
            retval += " . "
    return retval

def strNetTuple(tuple):
    return ("%s %d %s %d"
            %  (socket.inet_ntoa(tuple[0]),
                tuple[1],
                (socket.inet_ntoa(tuple[2])),
                tuple[3]))

def tlsHandshakeFinished(subtype):
    """
    The subtype for the Finished message ends up in the ciphertext, so
    we guess that a Handshake message with a mysterious subtype is a
    Finished message.
    """
    return (subtype == tlsConst.HandshakeType.finished
            or subtype not in (tlsConst.HandshakeType.hello_request,
                               tlsConst.HandshakeType.client_hello,
                               tlsConst.HandshakeType.server_hello,
                               tlsConst.HandshakeType.certificate,
                               tlsConst.HandshakeType.server_key_exchange,
                               tlsConst.HandshakeType.certificate_request,
                               tlsConst.HandshakeType.server_hello_done,
                               tlsConst.HandshakeType.certificate_verify,
                               tlsConst.HandshakeType.client_key_exchange,
                               tlsConst.HandshakeType.finished))

class Reassembler(object):
    """
    Give access to a TCP packet stream as a buffer of bytes.
    """
    def __init__(self, isn=None, direction=""):
        self.pkts = []
        self.seq = isn

        if len(direction) > 0:
            self.direction = direction + ": "

    def peek(self, numbytes):
        """
        Peek ahead at the input buffer without removing characters from it
        """
        return self.recv(numbytes, commit=False)

    def recv(self, numbytes, commit=True, raw=False):
        """
        Read numbytes bytes from the input buffer. If commit is
        True, the bytes are removed from the buffer; if false, the
        bytes remain in the buffer until pulled out later
        """
        out = array.array('c','\0'*numbytes)
        cur = self.seq
        bytes_remaining = numbytes
        extinguished = []

        insertion_point = 0

        if commit:
            DEBUG and log_debug("%stake %d bytes out of the reassembler"
                                % (self.direction, numbytes))

        # Note: add_pkt makes sure that packets are kept sorted by
        # seq# in the self.pkts array
        #
        # cur starts out somewhere in the first packet (not
        # necessarily at the beginning of it, since the last recv may
        # have been a partial read of the last packet)

        # FIXME: this scheme doesn't handle the case where sequence
        # numbers wrap around (also may not handle the case where sequence
        # numbers have the sign-bit on)
        for pkt in self.pkts:

            seq = pkt.get_seq()

            if self._compare_seq(seq, cur) > 0:

                # there's a hole in our data, have to wait for the
                # packet(s) that fill(s) it in to arrive
                # DEBUG and log_debug("reassembler return NONE, pkt.get_seq > cur")
                return None

            # pkt.get_seq() guaranteed <= cur
            pkt_end_seq = seq + pkt.get_payload_len()

            # wrap pkt_end_seq, if necessary
            #
            pkt_end_seq &= 0xffffffff

            if self._compare_seq(pkt_end_seq, cur) < 0:

                # packet ends before the current data point we're
                # looking at, so discard it
                extinguished.append(pkt)
            else:
                bytes_left_in_pkt = self._diff_seq(pkt_end_seq, cur)

                len_wanted = min(bytes_left_in_pkt, bytes_remaining)

                # Since we know that cur is inside this packet,
                # cur-beginning_of_packet tells us how far into the
                # packet the data we want is.
                #
                # TODO: test
                extraction_point = self._diff_seq(cur, seq)

                DEBUG and log_debug("out[%d:%d] = payload[%d:%d]"
                                    % (insertion_point,
                                       insertion_point + len_wanted,
                                       extraction_point,
                                       extraction_point + len_wanted))

                payload = pkt.get_payload()[extraction_point
                                            : (extraction_point
                                               + len_wanted)]

                out[insertion_point
                    :insertion_point+len_wanted] = array.array('c', payload)

                insertion_point += len_wanted
                bytes_remaining -= len_wanted
                cur += len_wanted

                # wrap cur, if necessary
                #
                cur &= 0xffffffff

                # A little redundant, with the check at the beginning
                # of the loop.
                if self._compare_seq(cur, pkt_end_seq) >= 0:
                    extinguished.append(pkt)

                if bytes_remaining == 0:
                    # we've got the bytes requested

                    if commit:
                        DEBUG and log_debug(("%s Reassembler:" % self.direction)
                                            + (" update current seqno to %d [0x%x]"
                                               % (cur, cur)))
                        self.seq = cur

                        # Remove any packets that we've extinguished
                        for p in extinguished:
                            self.pkts.remove(p)

                    DEBUG and log_debug("reassembler.recv return %d bytes"
                                        % len(out))
                    # DEBUG and log_debug("reassembler.recv returning (%s)"
                    #                     % binascii.hexlify(out))
                    if raw:
                        return out
                    else:
                        return out.tostring()

        # DEBUG and log_debug("reassembler.recv return NONE, got to end of packets")
        return None

    def add_pkt(self, pkt):
        """
        Adds a (possibly out of order) packet to the list of
        packets waiting to be read
        """

        seq = pkt.get_seq()

        # FIXME? This is a little dubious, the first packet we see
        # might not be the first packet on the connection.  self.seq
        # is none on the reverse path (probably should pick out the
        # SYN-ACK?)
        if self.seq == None:
            self.seq = seq
            DEBUG and log_debug(("%s Reassembler:" % self.direction)
                                + (" initialize current seqno to %d [0x%x]"
                                   % (self.seq, self.seq)))

        # a set of tuples to guard against the possibility that we get
        # a second packet with more data
        s = set([(p.get_seq(), p.get_payload_len()) for p in self.pkts])
        if (seq, pkt.get_payload_len()) in s:
            DEBUG and log_debug("%sSkip insert of duplicate packet"
                                % self.direction)
        else:
            DEBUG and log_debug("%sInsert pkt into reassembler: %s"
                                % (self.direction, pkt.pretty()))
            # We've already taken stuff out of this reassembler ---
            # are we beyond this packet already?
            if self.seq:
                if self._compare_seq(seq, self.seq) < 0:
                    DEBUG and log_debug(("%s Reassembler:"
                                         % self.direction)
                                        + (" have already processed"
                                           + " (at least part of) this packet"
                                           + (" pkt.seq: %d; self.seq: %d"
                                              % (pkt.get_seq(),
                                                 self.seq))))
                    payload_len = pkt.get_payload_len()
                    # TODO: test
                    if self._compare_seq(seq + payload_len, self.seq) < 0:
                        DEBUG and log_debug("Discarding already-processed pkt"
                                            + (" pkt start: %d;" % pkt.get_seq())
                                            + (" pkt end: %d;"
                                               % (pkt.get_seq()
                                                  + payload_len))
                                            + (" cur: %d" % self.seq))
                        return

            self.pkts.append(pkt)
            if len(self.pkts) > 1:
                self.pkts.sort(cmp=self._compare_pkt_seq)

            DEBUG and log_debug("%s Reassembler now contains %d bytes"
                                % (self.direction, self.len()))

    @staticmethod
    def _compare_pkt_seq(pkt1, pkt2):
        """
        Compare the sequence numbers in two packets

        See _compare_seq for details
        """

        seq1 = pkt1.get_seq()
        seq2 = pkt2.get_seq()

        return Reassembler._compare_seq(seq1, seq2)

    @staticmethod
    def _compare_seq(seq1, seq2):
        """
        Compare two sequence numbers, in the manner needed
        by sort or cmp.

        Sequence numbers wrap, so all the arithmetic is modular,
        which means that there is no pure arithmetic order on the
        set.  However, we can provide a suitable approximation by
        assuming that any two sequence numbers that are compared
        by this method will always fall with the same small partition
        of the set, and thus can be compared within that partition.
        What this means is that seq1 - seq2 *usually* gives the
        right answer, except when the partition spans 0, in which
        case we need to look at special cases.
        """

        # These are constants and could be computed elsewhere,
        # but I'm not sure that saves any real time in Python.
        #
        part_size = 0x10000000
        hi_start = 0x100000000 - part_size
        lo_end = part_size

        if (seq1 > hi_start) and (seq2 < lo_end):
            return -1
        elif (seq2 > hi_start) and (seq1 < lo_end):
            return 1
        else:
            return seq1 - seq2

    @staticmethod
    def _diff_seq(seq1, seq2):

        # These are constants and could be computed elsewhere,
        # but I'm not sure that saves any real time in Python.
        #
        part_size = 0x10000000
        hi_start = 0x100000000 - part_size
        lo_end = part_size

        res = seq1 - seq2

        if (seq1 > hi_start) and (seq2 < lo_end):
            return res - 0x100000000
        elif (seq2 > hi_start) and (seq1 < lo_end):
            return res + 0x100000000
        else:
            return res

    def len(self):
        """
        How much data is available in the accumulated packets?
        """
        # FIXME: handle situation in which seq#s wrap
        count = 0
        cur = self.seq
        for pkt in self.pkts:

            pkt_seq = pkt.get_seq()

            # there is a hole between where we are and the next packet
            # if pkt_seq > cur:
            if self._diff_seq(pkt_seq, cur) > 0:
                return count

            # not just a matter of adding up the payload lengths of
            # the packets:
            #  - stop when we get to a hole
            #  - remember that we may already have removed some of the
            #    bytes from (admittedly only the first) packet
            # bytes_left_in_pkt = (pkt_seq + pkt.get_payload_len()) - cur
            end_of_pkt = (pkt_seq + pkt.get_payload_len()) & 0xffffffff
            bytes_left_in_pkt = self._diff_seq(end_of_pkt, cur)

            # If you're confident the reassembler is not doing
            # something funny, there's no need for this chatty code
            # when debugging other things.
            #
            # DEBUG and log_debug(("%s Reassembler: current seq: %d [0x%x]"
            #                      % (self.direction, cur, cur))
            #                     + (" pkt.seq(%d [0x%x]), pkt.payload(%d)"
            #                        % (pkt.get_seq(),
            #                           pkt.get_seq(),
            #                           pkt.get_payload_len())))
            # DEBUG and log_debug(("bytes_left_in_pkt: %d;" % bytes_left_in_pkt)
            #                     + (" count before %d; count after %d"
            #                        % (count, count + bytes_left_in_pkt)))

            count += bytes_left_in_pkt
            cur += bytes_left_in_pkt
            cur &= 0xffffffff

        return count

class FlowMonitor(object):

    def __init__(self, tuple, cm, syn_options, isn):
        self.flow_tuple = tuple
        self.cm = cm
        self.syn_options = syn_options

        self.tunnel_type = const.UNKNOWN_TUNNEL
        self.isn = isn
        self.dr2dp = None

        self.flow_state = None
        self.last_seen = None
        self.hijack = None
        self.reassembler_forward = Reassembler(isn=isn, direction="C->S")
        self.reassembler_reverse = Reassembler(direction="S->C")

        # FlowMonitor knows three states:
        #  - Init
        #  - Hijacked
        # subclasses may have more states, all of which (plus Init)
        # cause the subclass handshake message to be called.
        DEBUG and log_debug("FM: state --> Init")
        self.state = 'Init'

        # Records decoy-to-client ttl to be used for covert-to-client packets.
        self.ttl = ''

        # Records decoy-to-client IP identifier field to be used for setting
        # covert-to-client packets.
        self.ip_identifier = ''
        self.ip_id_used = False

        self.log = logging.getLogger('cb.tcphijack.flow_mon')
        if (FlowMonitor.sentinels is None or 
            FlowMonitor.bittorrent_sentinels is None):
            print 'ERROR: sentinels not loaded, bailing out'

            # FIXME: complain if the sentinel table is empty after
            # being initialized, e.g.,
            # if FlowMonitor.sentinels.len() == 0:
            #     self.log.error("Sentinel table is empty")
            # (requires a .len() method for the sentinel objects,
            # which is why this is just a FIXME at the moment)
            #
            # Note that the SentinelManager runs asynchronously, which
            # may complicate the check on the sentinels
            
    def update_flow(self, pkt):
        """
        Keep track of how long since this flow has been active
        """
        self.last_seen = time.time()

    def init_hijack(self, pkt, isn):

        DEBUG and log_debug("FM: state[%s] --> Hijacked" % self.state)
        self.state = 'Hijacked'
        DEBUG and log_debug("Hijack flow %s %d; %s %d"
                            % (socket.inet_ntoa(pkt.get_src()),
                               pkt.get_sport(),
                               socket.inet_ntoa(pkt.get_dst()),
                               pkt.get_dport()))

        self.hijack = TCPHijack(pkt,
                                self.flow_tuple,
                                self.cm.opts,
                                self.send_to_dr,
                                self.syn_options,
                                isn)

    def handshake(self, pkt):
        """
        Subclasses should implement this
        """
        raise Exception("Unimplemented function")

    def traffic_from_client(self, pkt):
        """
        The flow from the client, either it's hijacked
        and we send it to the hijack object or it's still doing
        the curveball handshake and we monitor its progress
        """
        self.update_flow(pkt)

        DEBUG and log_debug("FM:traffic_from_client state: %s, pkt: (%s)"
                            % (self.state, pkt.pretty()))

        if self.state == 'Hijacked':
            # If we see a RST, abandon the connection
            # TODO: does this really close everything?
            flags = pkt.get_flags()
            if flags & dpkt.tcp.TH_RST:
                print 'detected client->decoy RST on tunnel'
                self.cm.remove_flow(self.flow_tuple)

            elif flags & dpkt.tcp.TH_FIN:
                print 'detected client->decoy FIN on tunnel'

                # We don't want to remove the flow right away; we
                # want to give a moment for the pkt to be delivered
                # and trigger a FIN-ACK, and let the endpoint for
                # this connection terminate the flow.
                # This is a bit of a hack.
                #
                self.hijack.traffic_from_client(pkt)
            else:
                self.hijack.traffic_from_client(pkt)

            return

        else:
            # If we see a RST or FIN, abandon the connection
            flags = pkt.get_flags()
            if flags & dpkt.tcp.TH_RST:
                print 'detected client->decoy RST on tunnel'
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)

            elif flags & dpkt.tcp.TH_FIN:
                print 'detected client->decoy FIN on tunnel'
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)

            else:
                self.handshake(pkt)

            return

    def traffic_to_client(self, pkt):
        """
        The flow from the server, either it's hijacked
        and we send it to the hijack object or it's still doing
        the curveball handshake and we monitor its progress
        """
        self.update_flow(pkt)

        # Record the ttl of decoy-to-client packets to be used in setting
        # the ttl field of covert-to-client packets; simply use the last
        # recorded ttl from the deocy
        self.ttl = pkt.get_ttl()

        # Record the IP identifier of decoy-to-client packets to be used
        # in setting the IP identifier field of covert-to-client packets.
        self.record_ip_identifier(pkt.get_identifier())

        # DEBUG and log_debug("FM:traffic_to_client(%s)" % pkt.pretty())
        DEBUG and log_debug("FM:traffic_to_client, state = %s" % self.state)

        if self.state == 'Hijacked':

            # once hijacked, suppress data packets from decoy
            if pkt.get_payload_len() > 0:
                return;

            # change RST to ACK
            flags = pkt.get_flags()
            if flags & dpkt.tcp.TH_RST:
                flags &= ~dpkt.tcp.TH_RST
                flags |= dpkt.tcp.TH_ACK
                pkt.set_flags(flags)

            self.send_to_dr(pkt, False) # false indicates decoy packet

            # If we see a FIN, abandon the connection
            # TODO: does this really close everything?
            if flags & dpkt.tcp.TH_FIN:
                print 'detected client<-decoy FIN on tunnel'
                self.cm.remove_flow(self.flow_tuple)

            return

        else:

            # If we see a RST or FIN, abandon the connection
            flags = pkt.get_flags()
            if flags & dpkt.tcp.TH_RST:
                print 'detected client->decoy RST on tunnel'
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)

            elif flags & dpkt.tcp.TH_FIN:
                print 'detected client->decoy FIN on tunnel'
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)

            self.handshake(pkt)
            return

    def handle_icmp(self, pkt, reverse = False):
        """
        Handle ICMP packet on flow.
        """
        DEBUG and log_debug("FM: handle ICMP packet")

        # decoy->client ICMP (client->decoy embedded IP)
        #    handshake: pass through
        #    hijacked:  pass through (adversary sending them? special cases?)
        if reverse == False:
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through decoy->client icmp")
            return

        # client->decoy ICMP (decoy->client embedded IP)

        # unidirectional; pass through
        if self.tunnel_type == const.CREATE_HTTP_UNI_TUNNEL or \
           self.tunnel_type == const.HTTP_UNI_TUNNEL:
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through unidirectional icmp")
            return

        # incomplete hijack of flow; pass through
        if self.hijack == None:
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through icmp on unhijacked flow")
            return

        # invalid icmp type; pass through
        type = pkt.get_icmp_type()
        if type != Packet.ICMP_TYPE_DEST_UNREACH and 	\
           type != Packet.ICMP_TYPE_REDIRECT and	\
           type != Packet.ICMP_TYPE_TIME_EXCEED and	\
           type != Packet.ICMP_TYPE_PARAM_PROB:
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through icmp with invalid type")
            return

        # embedded ip packet not tcp; pass through
        if pkt.is_embed_tcp() == False:
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through icmp with no embedded tcp")
            return

        # icmp destination fails to match decoy; pass through
        (src, sport, dst, dport) = self.flow_tuple
        if dst != pkt.get_dst():
            self.cm.send_to_dr_endpoint(str(pkt))
            DEBUG and log_debug("FM: pass through icmp with invalid dst")
            return

        # bidirectional (http, tls)
        #    - rewrite ip header of the icmp packet to change the src/dst
        #      addresses to the local terminal addresses
        #    - rewrite icmp body so that all references to decoy are replaced
        #      with the local terminal address
        #    - write the updated icmp packet to the hijacked tunnel
        assert(self.hijack)

        (hsrc, hsport, hdst, hdport) = self.hijack.hijack_tuple
        pkt.set_src(hsrc)
        pkt.set_dst(hdst)
        pkt.set_icmp_src(hdst, hdport)
        pkt.set_icmp_dst(hsrc, hsport)

        TCPHijack.hijack_manager.tun.write(str(pkt))

        return

    # The HTTP and TLS flow monitors call dr2dp.send_to_dr() which is
    # equivalent to calling self.cm.send_to_dr_endpoint().
    # Should the HTTP and TLS flow monitors just call this method?
    #
    def send_to_dr(self, pkt, covert = True):
        """
        This comes from a hijack'd flow, send it to the client
        """
        try:
            DEBUG and log_debug("FM:send_to_dr, state = %s; %s"
                                % (self.state, pkt.pretty()))
        except AttributeError:
            DEBUG and log_debug("FM:send_to_dr (data not instance of packet class)")

        self.update_flow(pkt)

        # set the ttl of covert-to-client packets
        if covert == True and self.ttl != '':
            pkt.set_ttl(self.ttl)

        # set the IP identifier of packets (both decoy and covert to client)
        self.set_ip_identifier(pkt, covert)

        self.cm.send_to_dr_endpoint(str(pkt))

    def record_ip_identifier(self, identifier):
        """
        For now, only record the IP identifier as is, assuming that the
        identifier is simply incrementing by one. More sophisticated
        recording algorithms can be used in the future if necessary.

        The identifier field is no longer recorded from decoy-to-client
        packets once the first covert-to-client packet has been sent.

        """

        if self.ip_id_used == False:
            self.ip_identifier = identifier

    def set_ip_identifier(self, pkt, covert):
        """
        Set the IP identifier field of packets outgoing to the client.
        """

        # Simply use the IP identifier field already within decoy-to-client
        # packets if no covert-to-client packets have been sent on the flow.
        if covert == False and self.ip_id_used == False:
            return

        # The first covert-to-client packet has been sent on the flow.
        if covert == True and self.ip_id_used == False:
            self.ip_id_used = True

        # An identifier really should have been recorded by now; simply
        # use the identifier already included within the packet.
        if self.ip_identifier == '':
            return

        # Simply increment the IP identifier for now. More sophisticated
        # algorithms can be used in the future if necessary.
        if self.ip_identifier >= 0xffff:
            self.ip_identifier = 0
        else:
            self.ip_identifier += 1

        pkt.set_identifier(self.ip_identifier)



def get_http_req(tuple, reassembler, recv_buf):
    """
    reads an HTTP request from the recv_buf (after extending the
    recv_buf from the reassembler if there is anything pending)
    """

    if tuple[1] == 80:
        DEBUG and log_debug("conn mon: this case should not occur")

    elif tuple[3] == 80:

        # If there's anything waiting in the reassembler,
        # fetch it and append it to self.recv_buf
        #
        avail_len = reassembler.len()
        if avail_len > 0:
            new_buf = reassembler.recv(avail_len)
            if avail_len != len(new_buf):
                print 'avail %d got %d' % (avail_len, len(new_buf))
            recv_buf += new_buf

        # If self.recv_buf is empty, then there's no rec
        # waiting.
        #
        if not recv_buf:
            return [None, recv_buf]

        # if we have reached the END_HEADER, lop off the first
        # request, update self.recv_buf, and return the request
        #
        end_offset = recv_buf.find(const.END_HEADER)
        if end_offset > 0:
            rec_len = end_offset + len(const.END_HEADER)
            msg = recv_buf[:rec_len]
            recv_buf = recv_buf[rec_len:]
            return [msg, recv_buf]
        else:
            # print "not got it buf len %d" % len(self.recv_buf)
            return [None, recv_buf]
    else:
        DEBUG and log_debug("Error: packet is not http")

def get_full_sentinel_hex( sentinel ):
    """
    Return the sentinel and sentinel label
    """

    if sentinel.startswith( const.SENTINEL_DEADBEEF ):
        sentinel_hex = const.FULL_SENTINEL_DEADBEEF
    else:
        sentinel_hex = sentinel + FlowMonitor.sentinels[ sentinel ]

    return sentinel_hex

def check_for_sentinel( msg ):

    cookie = http_util.get_header('Cookie: ', msg)

    if cookie == '-1':
        return -1

    # we assume that the cookie string is properly formatted,
    # and does not start or end with COOKIE_SEPARATOR
    #
    cookies = cookie.split(const.COOKIE_SEPARATOR)
    kv_pairs = [cookie_kv.split('=') for cookie_kv in cookies]

    sentinels = [val for (key, val) in kv_pairs
            if val[:const.SENTINEL_HEX_LEN] in FlowMonitor.sentinels or
                val.startswith(const.SENTINEL_DEADBEEF) and permit_deadbeef]
    if len(sentinels) > 1:
        return -1

    # Check whether the candidate sentinel triggered a false positive in the
    # Bloom filter but doesn't actually match any real sentinels
    #
    if len(sentinels) < 1:
        return -1

    handshake_ID = sentinels[0]
    if len(handshake_ID) >= (const.SENTINEL_HEX_LEN +
            const.NONCE_CLIENT_BYTE_LEN):
        return handshake_ID
    else:
        return -1

def get_http_tunnel_type(msg, http_bi_tunnel_tag, http_uni_tunnel_tag):

    cookie = http_util.get_header('Cookie: ', msg)

    if cookie == '-1':
        return -1

    # we assume that the cookie string is properly formatted,
    # and does not start or end with COOKIE_SEPARATOR
    #
    cookies = cookie.split(const.COOKIE_SEPARATOR)
    kv_pairs = [cookie_kv.split('=') for cookie_kv in cookies]

    for (_key, val) in kv_pairs:
        if val == http_bi_tunnel_tag:
            return const.CREATE_HTTP_BI_TUNNEL
        elif val == http_uni_tunnel_tag:
            return const.CREATE_HTTP_UNI_TUNNEL

    return const.UNKNOWN_TUNNEL

class HTTPUnknownFlowMonitor(FlowMonitor):

    def __init__(self, tupl, cm, syn_options, isn, dr2dp):
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.recv_buf = ''
        self.dr2dp = dr2dp
        self.host_ip = str(socket.inet_ntoa(self.flow_tuple[2]))
        self.host_name = self.host_ip
        self.nonce_client = None
        self.full_sentinel_hex = None
        self.sentinel = None
        self.initial_req = None

    def traffic_to_client(self, pkt):

        self.dr2dp.send_to_dr(pkt)

    def traffic_from_client(self, pkt):
        """
        Process packets coming from the client
        """

        self.dr2dp.send_to_dr(str(pkt.clone()))

        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self.cm.remove_flow(self.flow_tuple)
            return

        self.reassembler_forward.add_pkt( pkt )

        tuple = pkt.get_tuple()

        while True:
            # Check whether pkt contains HTTP Request
            #
            http_msg, self.recv_buf = get_http_req(
                    tuple, self.reassembler_forward, self.recv_buf)
            if http_msg is None:
                return

            # Check that msg contains valid sentinel
            #
            handshake_ID = check_for_sentinel(http_msg)
            if handshake_ID == -1:
                self.cm.remove_flow(self.flow_tuple)
                return

            identified_tunnel = self.determine_tunnel_type(
                    http_msg, handshake_ID)
            if identified_tunnel == True:
                return

    def determine_tunnel_type(self, http_msg, handshake_ID):

        self.initial_req = http_msg
        self.sentinel = handshake_ID[ : const.SENTINEL_HEX_LEN]
        self.full_sentinel_hex = get_full_sentinel_hex(self.sentinel)

        try:
            # Pull info out of Cookie
            #
            offset = const.SENTINEL_HEX_LEN + const.NONCE_CLIENT_HEX_LEN
            self.nonce_client = handshake_ID[ const.SENTINEL_HEX_LEN : offset ]

            # Create BI http tunnel_type_tag
            #
            tunnel_type_hash = hmac.new(
                    const.HTTP_BI_TUNNEL + self.nonce_client,
                    self.full_sentinel_hex[const.SENTINEL_HEX_LEN:],
                    hashlib.sha256 ).digest()
            bi_tunnel_tag = tunnel_type_hash.encode("hex")

            # Create UNI http tunnel_type_hash
            #
            tunnel_type_hash = hmac.new(
                    const.HTTP_UNI_TUNNEL + self.nonce_client,
                    self.full_sentinel_hex[const.SENTINEL_HEX_LEN:],
                    hashlib.sha256 ).digest()
            uni_tunnel_tag = tunnel_type_hash.encode("hex")

            # Default self.host is the decoy ip address, set in init
            # Here, we check whether the host name in the packet can be pulled
            # off. If so, we use this host name instead since it is typically
            # the name, not the ip address
            #
            host = http_util.get_header_value("host", http_msg)
            if host != '-1':
                self.host_name = host

            # Try to determine tunnel type
            #
            self.tunnel_type = get_http_tunnel_type(
                    http_msg, bi_tunnel_tag, uni_tunnel_tag )

            if self.tunnel_type == const.UNKNOWN_TUNNEL:
                return False
            else:
                return True

        except TypeError:
            return False



class HTTPBiFlowMonitor(FlowMonitor):

    def __init__(self, old_flow_mon, dr2dp):

        tupl          = old_flow_mon.flow_tuple
        cm            = old_flow_mon.cm
        syn_options   = old_flow_mon.syn_options
        isn           = old_flow_mon.isn
        self.host_name = old_flow_mon.host_name
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.dr2dp = old_flow_mon.dr2dp
        self.reassembler_forward = old_flow_mon.reassembler_forward
        self.recv_buf = old_flow_mon.recv_buf

        self.handshake_ID = None
        self.nonce_client = None
        self.nonce_dp = None
        self.premaster = None
        self.signature = None
        self.decoy_host_name = '-1'
        self.content_type = '-1'
        self.decoupled_ID = None
        self.extra_d2c_key = None

        self.pubkey_dp = security_util.obtain_pubkey_dp(self)
        self.privkey_dp = privkey_util.obtain_privkey_dp(self)

        self.re_http_resp = re.compile('HTTP/1.1 * 200')

        self.tunnel_type = const.HTTP_BI_TUNNEL

    def handshake(self, pkt):
        """
        Determine whether pkt is from the client or the server
        """

        if pkt.get_sport() == 80:
            self.handshake_server_to_client(pkt)
        else:
            self.handshake_client_to_server(pkt)

    def handshake_client_to_server(self, pkt):
        """
        Process packets coming from the client
        """

        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        self.reassembler_forward.add_pkt(pkt)

        # Check whether pkt contains HTTP Request
        #
        tuple = pkt.get_tuple()
        [msg, self.recv_buf] = get_http_req(
                tuple, self.reassembler_forward, self.recv_buf )

        if msg is None:
            self.dr2dp.send_to_dr( str(pkt) )
            return

        # Process HTTP request from client
        #
        if ( re.search('[Cc]onnection: * [Cc]lose', msg) ):
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)

        if self.state == const_dp.STATE_2:
            self.dr2dp.send_to_dr( str(pkt) )
            self.handshake_init( msg )

            self.decoy_host_name = http_util.get_header_value( "host", msg )
            if self.decoy_host_name == '-1':
                self.decoy_host_name = ''

        elif self.state == const_dp.STATE_4:
            self.get_premaster( msg, pkt )

        else:
            print "no cookie so no sentinel"
            self.log.debug("No cookie so no sentinel")
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)

    def handshake_server_to_client(self, pkt):
        """
        Process packets coming from server
        """
        # TODO: Assumption that we can fit everything we
        #       need to in one single pkt from DH
        if self.state == const_dp.STATE_2_5:
            self.waiting_for_DH_response(pkt)
        else:
            self.dr2dp.send_to_dr( str(pkt) )

    def handshake_init(self, msg):
        """
        State 2:  Init
        """
        self.handshake_ID = check_for_sentinel( msg )

        if self.handshake_ID != -1:

            self.sentinel = self.handshake_ID[ : const.SENTINEL_HEX_LEN]

            try:
                offset = const.SENTINEL_HEX_LEN + const.NONCE_CLIENT_HEX_LEN
                self.nonce_client = self.handshake_ID[
                        const.SENTINEL_HEX_LEN : offset].decode("hex")

            except TypeError:
                print "handshake ID cannot be hex decoded"
                self.log.debug("No sentinel")
                self.cm.remove_flow(self.flow_tuple)

            # Generate 16 hex digits = 8 byte random nonce
            #
            self.nonce_dp = cb_random.gen_rand_bytes(self, const.NONCE_DP_BYTE_LEN)

            self.state = const_dp.STATE_2_5

        else:
            self.log.debug("No sentinel")
            self.cm.remove_flow(self.flow_tuple)

    def waiting_for_DH_response(self, pkt):
        """
        State 2.5:  waiting for http response from DH

         A.   Set-Cookie :  SESSSIONID=Decoupled_ID; Domain=.foo.com; Path=/

         B.      Payload :  E_KeyFullSentinel( Salt_1 + Nonce_DP )

         C.                 Signature_DPPriv( Salt_1   +
                                              Nonce_DP +
                                              Set-Cookie :  XXX +
                                              Handshake_ID )
        Decoupled_ID = RandomString
        XXX = SESSSIONID=Decoupled_ID; Domain=.foo.com; Path=/ +
        """
        p = pkt.get_payload()
        self.content_type = http_util.get_header_value( "content-type", p )
        if self.content_type == '-1':
            self.content_type = ''

        try:
            # Note: if DH response is unconventional (more whitespace
            #       between 1.1 and 200, or some string not equal to
            #       OK), we do not hijack.
            #
            header_start = p.index('HTTP/1.1 200 OK')
            header_end = p.index(const.END_HEADER)

            # Determine available free space in response
            #
            (new_p, free_bytes) = self.get_free_space( p, header_start, header_end )

            if new_p == -1:
                print "Pkt does not contain full http response header"
                self.dr2dp.send_to_dr(str(pkt))
                return

            # A. SESSSIONID=RandomString; Domain=.foo.com; Path=/
            #
            # Create new cookie for client to use so client doesn't have
            # to keep using sentinel=nonce as a cookie
            #
            new_cookie = self.create_new_cookie()

            # B. E_KeyFullSentinel( Salt_1 + Nonce_DP )
            #
            # Compute key from sentinel label
            #
            self.sentinel_hex = get_full_sentinel_hex( self.sentinel )
            [self.extra_d2c_key] = security_util.obtain_extra_keys(
                self, self.sentinel_hex)

            salt_1 = cb_random.gen_rand_bytes(self, const.SALT_BYTE_LEN);
            enc_nonce_dp = security_util.encrypt_text( self,
                salt_1 + self.nonce_dp, self.extra_d2c_key, False, True, False )

            # C. Signature_DPPriv( Salt_1 + Nonce_DP + Set-Cookie:  XXX + Handshake_ID )
            #
            # DP signs the client msg that it just received and
            # all other info that it is sending back
            #
            text = ( salt_1 + self.nonce_dp + new_cookie + self.handshake_ID )

            self.signature = privkey_util.signature_privkey_dp(self, text)
            covert_msg = self.signature + enc_nonce_dp

            # Send response back to client
            #
            self.send_http_resp_new_cookie(
                header_start, header_end, pkt, new_cookie,
                p, new_p, covert_msg, free_bytes)

        except ValueError:
            self.dr2dp.send_to_dr(str(pkt))

    def send_http_resp_new_cookie(self,
        header_start, header_end, pkt, new_cookie, orig_payload,
        no_cookie_payload, covert_msg, free_bytes):
        """
        Content-Length case
        """
        try:
            splits = re.split('^[Cc]ontent-[Ll]ength\s*:\s*',
                              no_cookie_payload, 1, re.MULTILINE)
            if len(splits) == 2:
                clen_start = len(no_cookie_payload) - len(splits[1])
            else:
                raise ValueError('cannot find content-length')

            clen_payload       = no_cookie_payload[ clen_start : ]
            clen_end           = clen_payload.index(const.END_LINE)
            clen               = clen_payload[ : clen_end ]
            before_clen_header = no_cookie_payload[ : clen_start ]
            after_clen_header  = clen_payload[clen_end : ]

            # diff_len is how much padding needs to be added to payload to
            # match content length
            #
            pkt_clen = len( orig_payload[header_end + len(const.END_HEADER) : ] )
            diff_len = pkt_clen - len(covert_msg) - len(new_cookie) + free_bytes
            clen_new = str(int(clen) - len(new_cookie) + free_bytes)

            new_payload = (
                    before_clen_header + clen_new +
                    after_clen_header[ : -len(const.END_LINE) ] +
                    new_cookie + const.END_LINE + covert_msg )

            if diff_len < 0:
                print "Error: not enough free space in DH response"
                DEBUG and log_debug("Error: not enough free space in DH response")
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            if diff_len > 0:
                byte_filler = cb_random.gen_rand_bytes(self, diff_len)
                byte_filler = byte_filler.encode("hex")
                new_payload = new_payload + byte_filler[ : diff_len ]

            if len(new_payload) != len(orig_payload):
                print "Changing content length cannot be done easily"
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            pkt.set_same_size_payload(new_payload, header_start, len(new_payload))
            pkt.update_cksum()
            self.dr2dp.send_to_dr(str(pkt))
            self.state = const_dp.STATE_4
            return

        except ValueError:
            DEBUG and log_debug("No content length, probably chunk encoding")

        """
        Chunk encoding case
        """
        try:
            if http_util.get_header_value('Transfer-Encoding',
                    orig_payload) == 'chunked':
                DEBUG and log_debug("Contains chunk encoding")
            else:
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            end_header      = orig_payload.index( const.END_HEADER ) + len(const.END_HEADER)
            chunk_payload   = orig_payload[ end_header : ]
            end_chunk_len   = chunk_payload.index( const.END_LINE ) + len(const.END_LINE)
            chunk_len       = chunk_payload[ : end_chunk_len ]
            chunk           = chunk_payload[ end_chunk_len : ]
            int_chunk_len   = int(chunk_len, 16)
            new_header      = no_cookie_payload[ : - len(const.END_HEADER) ]
            covert          = covert_msg.encode("hex")

            # Check whether entire chunk contained in first pkt.
            # Might have multiple chunks, don't want to overwrite
            #
            not_full_chunk = False
            if ( len( chunk )  < int_chunk_len ):
                print "Full chunk not contained in pkt"
                not_full_chunk = True

            # Might have multiple chunks, don't want to overwrite
            #
            if ( not_full_chunk == True and len(covert) <= ( len(chunk) - len(const.END_LINE)) or
                 not_full_chunk == False and len(covert) <= ( int_chunk_len - len(const.END_LINE))) :
                remaining_chunk = chunk[ len(covert) : ]
            else:
                print "Not enough space in DH response"
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            # Determine amount of byte padding to add
            # This new payload is a temporary payload used to
            # determine amount of byte padding to add.
            #
            # TODO: compute lengths directly, rather than creating
            #       string and computing length of string
            #
            new_payload = (
                    new_header + const.END_LINE + new_cookie + const.END_LINE +
                    chunk_len + covert + remaining_chunk )

            diff_len = len(orig_payload) - len(new_payload)
            if diff_len < 0:
                print "Not enough space in DH response"
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            byte_filler = cb_random.gen_rand_bytes(self, (diff_len))
            byte_filler = byte_filler.encode("hex")

            # Get new chunk length in hex
            #
            new_chunk_len = chunk_len[ :- len(const.END_LINE)]
            int_clen = int(new_chunk_len, 16)
            int_clen += int(diff_len)
            new_chunk_len = hex( int_clen )
            new_chunk_len = new_chunk_len[2:] # Removing initial 0x for hex

            # Create final new payload for pkt with correct chunk length
            #
            new_payload = (
                    new_header + const.END_LINE + new_cookie + const.END_LINE +
                    new_chunk_len + const.END_LINE + covert +
                    byte_filler[:diff_len] + remaining_chunk )

            if len(new_payload) != len(orig_payload):
                print "Changing chunk length cannot be done easily"
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)
                return

            pkt.set_same_size_payload( new_payload, header_start, len(new_payload) )
            pkt.update_cksum()
            self.dr2dp.send_to_dr(str(pkt))
            self.state = const_dp.STATE_4

        except ValueError:
            print "Neither content length nor chunk encoding: don't hijack"
            DEBUG and log_debug("Neither content length nor chunk encoding: don't hijack")
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)

    def get_premaster(self, msg, pkt):
        """
        State 4:  Get premaster

            HTTP_CT_DP.py is where the HTTP response for
            State 4 is actually sent back
        """

        self.content_type = http_util.get_header_value("content-type", str(msg))
        if self.content_type == '-1':
            self.content_type = ''

        self.server_name = http_util.get_header_value("server", str(msg))
        if self.server_name == '-1':
            self.server_name = ''

        # Pull out encrypted message from header
        #
        url = http_util.get_request_uri(msg)
        if url == None:
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        # If anything goes wrong when parsing the request to find
        # the premaster, then abandon the connection.  It's not a
        # Curveball client -- it's someone pretending to be Curveball,
        # or an innocent false positive sentinel match.
        #
        try:
            hex_text = url
            zip_text = hex_text.decode( "hex" )
            bin_text = zlib.decompress( zip_text )

            enc_auth_text = binascii.unhexlify( bin_text )
            enc_text = enc_auth_text[ : -const.HASH_BYTE_LEN ]
            auth_text = enc_auth_text[ -const.HASH_BYTE_LEN : ]

            # Load up private key and decrypt message
            #
            text = privkey_util.privkey_decrypt( self, enc_text )

            # Pull out premaster sent by Client and check hmac
            #
            self.premaster       = text[ : const.PREMASTER_BYTE_LEN ]
            self.seqNum_C2D_Rand = text[ const.PREMASTER_BYTE_LEN : ]

            pubkey_dp = security_util.obtain_pubkey_dp(self)

            text_ = ( self.premaster + self.seqNum_C2D_Rand +
                      self.decoupled_ID + self.nonce_dp )

        except BaseException, exc:
            print 'ERROR: no premaster in request [%s]' % str(exc)
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        auth_text_ = hmac.new( text_, self.pubkey_dp, hashlib.sha256 ).digest()

        # Check that hmac client generated matches hmac that DP generated
        #
        if auth_text != auth_text_:
            print 'hmacs do not match'
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
        else:
            # TODO: Using packet's seq number for isn, not fragment safe!
            #
            self.hijack_rec = text
            try:
                self.init_hijack(pkt, pkt.get_seq()-1)
            except Exception as e:
                log_error("Can't init hijack: %s" % str(e))
                self.dr2dp.send_to_dr(str(pkt))
                self.cm.remove_flow(self.flow_tuple)

    def create_new_cookie(self):
        """
        Create new cookie for client to use so client doesn't have
        to keep using sentinel=nonce as a cookie
        """
        self.decoupled_ID = cb_random.gen_rand_bytes( self, const.DECOUPLED_ID_BYTE_LEN )

        domain_frag = re.sub('^[Ww]{3}\.', '', self.decoy_host_name)
        if ( len( domain_frag ) > 0 and
             len( domain_frag ) < const.MAX_SET_COOKIE_DOMAIN_LEN ) :
            domain = ' Domain=.' + domain_frag + ';'
        else:
            domain = ''

        new_cookie = ( 'Set-Cookie: ' + const.COOKIE_NAME + '=' +
                       str(self.decoupled_ID.encode("hex")) + ";" +
                       domain + ' Path=/' + const.END_LINE )

        return new_cookie

    def get_free_space( self, orig_p, i, j ):
        """
        Determine available free space in response
        Remove Set-Cookie sent by decoy (will be replaced later)
        """
        new_p = ''
        p = orig_p[i:j]
        free_bytes = 0

        # Check whether pkt contains full http response header
        #
        if not (re.search(const.END_HEADER, orig_p)):
            print "Error: not full header in pkt"
            return -1, -1

        while True:
            try:
                # TODO: assumption: the decoy sends us proper
                # Set-Cookie lines, not things like 'X-Set-Cookie',
                # which will also match this
                #
                header = p.index('Set-Cookie: ')

                if (re.search('Path', p[header:])):
                    path = p[header:].index('Path')
                elif (re.search('path', p[header:])):
                    path = p[header:].index('path')
                elif (re.search('Domain', p[header:])):
                    path = p[header:].index('Domain')
                else:
                    path = p[header:].index('domain')

                if (re.search(const.END_LINE, p[path:])):
                    finish = path + p[path:].index(const.END_LINE) + len(const.END_LINE)
                else:
                    finish = path + p[path:].index(const.END_HEADER) + len(const.END_HEADER)

                cookie = p[header:finish]
                free_bytes += len(cookie)

                # Create new packet with cookie field removed
                #
                new_p += p[:header]

                # Packet comprising remaining stuff after removed cookie
                #
                p = p[ header + len(cookie) : ]

            except ValueError:
                # Should eventually hit this ValueError. At this point, have
                # removed all Cookies or packet never contained cookies
                #
                new_p += p + const.END_HEADER
                break

        return new_p, free_bytes




class HTTPUniFlowMonitor(FlowMonitor):

    def __init__(self, old_flow_mon, dr2dp, uni_ct_dp):

        tupl = old_flow_mon.flow_tuple
        cm = old_flow_mon.cm
        syn_options = old_flow_mon.syn_options
        isn = old_flow_mon.isn
        self.host_name = old_flow_mon.host_name
        self.sentinel = old_flow_mon.sentinel
        self.full_sentinel_hex = old_flow_mon.full_sentinel_hex
        self.nonce_client = old_flow_mon.nonce_client.decode("hex")
        self.initial_req = old_flow_mon.initial_req
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.dr2dp = old_flow_mon.dr2dp
        self.reassembler_forward = old_flow_mon.reassembler_forward
        self.recv_buf = old_flow_mon.recv_buf
        self.re_http_resp = re.compile('HTTP/1.1 * 200')
        self.handshake_ID = None
        self.nonce_dp = None
        self.premaster = None
        self.seqno = None
        self.is_first = True
        self.mole = None
        self.host_ip = str(socket.inet_ntoa(self.flow_tuple[2]))
        self.http_mole_encoder = HttpMoleCryptoEncoder(
                self.host_name, self.full_sentinel_hex)
        self.uni_ct_dp = uni_ct_dp
        try:
            self.ctdp_src_sock = socket.socket()
            self.ctdp_src_sock.connect(('localhost', const.HTTP_UNI_CT_DP_PORT))
            self.ctdp_src_sock.setblocking(False)
        except socket.error:
            self.ctdp_src_sock = None

        self.session_key = self.full_sentinel_hex[const.SENTINEL_HEX_LEN : ]
        self.rc4_handshake_c2d = RC4.RC4(self.session_key)
        self.rc4_handshake_d2c = RC4.RC4(self.session_key)

        # We don't use the host or session_key parameters because the
        # only thing we use this encoder for is its digest method, which
        # does not depend on anything except the text.
        #
        self.encoder = HttpMoleCryptoEncoder('fakehost', 'fakekey')
        self.decoupled_ID = None
        self.extra_d2c_key = None
        self.pubkey_dp = security_util.obtain_pubkey_dp(self)
        self.privkey_dp = privkey_util.obtain_privkey_dp(self)
        self.tunnel_type = const.HTTP_UNI_TUNNEL

    def handshake(self, pkt):
        """
        Determine whether pkt is from the client or the server
        """
        if pkt.get_sport() == 80:
            self.dr2dp.send_to_dr( str(pkt) )
            self.log.debug("Ignoring reverse traffic: unidirectional")
        else:
            self.handshake_client_to_server(pkt)

    def handshake_client_to_server(self, pkt):
        """
        Process packets coming from the client
        """

        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        if len(pkt.get_payload()) <= 0:
            self.dr2dp.send_to_dr(str(pkt))
            return

        self.reassembler_forward.add_pkt(pkt.clone())

        # Create and/or use Mole
        #
        pkt_clone = pkt.clone()
        pkt_seq_no = pkt_clone.get_seq()
        if self.mole == None:
            self.create_mole_tunnel(pkt_seq_no)
        self.use_mole_tunnel(pkt_seq_no, pkt_clone)

        # Process all queued up HTTP requests
        #
        tuple = pkt.get_tuple()
        while True:

            [http_msg, self.recv_buf] = get_http_req(
                tuple, self.reassembler_forward, self.recv_buf)

            if http_msg == None:
                return

            if self.state == const_dp.STATE_2_UNI:
                self.handshake_init(http_msg)

            elif self.state == const_dp.STATE_4_UNI:
                self.handshake_hijacked(http_msg)

    def create_mole_tunnel(self, tcp_seq_no):
        """
        We create the mole tunnel immediately because we need to start
        rewriting pkts immediately (to handle tcp segmentation) even
        before the handshake has completed. This does introduce some
        vulnerabilities.
        """

        # Create mole and insert welcome into mole queue. Because
        # the mole creates its own requests of the things in its
        # queue, we want to only insert the welcome string, not
        # a full request
        #
        self.mole = MoleTunnelDp(
                self.http_mole_encoder, tcp_seq_no, const.HTTPU_CURVEBALLHELLO)

        self.uni_ct_dp.setMole(self.mole)

        # Set up buffering for mole tunnel
        #
        self.partition_size = 0x200000
        self.highest_partition = 0xffffffff / self.partition_size
        self.max_partition = tcp_seq_no / self.partition_size
        if self.max_partition == 0:
            self.min_partition = self.highest_partition
        else:
            self.min_partition = self.max_partition - 1
        self.gen_wrap = 0

    def use_mole_tunnel(self, seq_no, pkt):
        """
        State 4:  Ready

        Extract covert data from request, forward on modified pkt
        """

        # Use a heuristic-based state machine to determine the
        # "unwrapped" sequence number, based on the original sequence number.
        # We assume that the sequence numbers are seen in a semi-sequential
        # order such that if we use a window of osize 0x1000000 (or any other
        # suitable value) that evenly divides 2^32), then we can can partition
        # the 32-bit space into partitions of this window size such:
        #
        # a) two consecutively observed sequence numbers must either be
        # within the same partition, or two adjacent partition
        #
        # b) if the highest sequence number observed is in partition N, then
        # the next observation must be in partition N or N-1, N, or N+1 (all
        # modulo the number of partitions).
        #
        # Property b) means that we don't have to move forward constantly,
        # but there is a limit to how far "backward" we can go once we have
        # seen any sequence number in a given partition.
        #
        # We can use properties a) and b) together to determine when a wrap
        # has happened, and add the proper amount to the "effective" sequence
        # number.

        # figure out which partition we are in, and update self.max_partition
        #
        curr_partition = seq_no / self.partition_size

        if ((curr_partition == 0) and
                (self.max_partition == self.highest_partition)):
            self.max_partition = 0
            self.min_partition = self.highest_partition

            print 'WRAPPED partitions %x %x' % (
                    self.min_partition, self.max_partition)

        elif curr_partition > self.max_partition:
            self.max_partition = curr_partition
            self.min_partition = curr_partition - 1
            if self.min_partition == 0:
                self.gen_wrap += 0x100000000

            print 'partitions %x %x' % (
                    self.min_partition, self.max_partition)

        # TODO: I think this still has a latent bug when the
        # first segment is in partition 1 or 0, because we
        # assume that the only way we see partitions 0 and 1 is
        # after wrapping.
        #
        if (curr_partition == 0) and (self.max_partition == 0):
            increment = 0x100000000
        else:
            increment = 0

        eff_seq_no = seq_no + increment + self.gen_wrap

        # Obtain data to put in pkt to forward to DH
        #
        len_payload = len(pkt.get_payload())
        self.mole.extend(eff_seq_no + len_payload)
        new_payload = self.mole.copy(eff_seq_no, len_payload)

        # discard 2MB from the queue whenever the
        # queue grows to be more than 4MB.
        #
        # FIXME: this is a weak and incorrect heuristic;
        # it should depend on the current window size, not some
        # numbers I made up out of thin air
        #
        too_full_size = 4 * 1024 * 1024
        trim_size = too_full_size / 2

        pending = self.mole.encoded_pending
        head_seq = pending.get_base() + pending.get_offset()

        if pending.get_len() > too_full_size:
            print 'DISCARDING FROM MOLE QUEUE seq_no %.8x' % eff_seq_no
            self.mole.reset_base(head_seq + trim_size)

        # Forward on modified pkt to DH
        #
        pkt.set_same_size_payload(new_payload, 0, len(new_payload))
        pkt.update_cksum()
        self.dr2dp.send_to_dr(str(pkt))

    def handshake_init(self, http_msg):
        """
        State 2:  Init
        """

        # Process payload
        #
        self.handshake_ID = check_for_sentinel(http_msg)
        if self.handshake_ID == -1:
            self.log.debug("No sentinel")
            self.cm.remove_flow(self.flow_tuple)

        # We already computed this info from the first pkt. Now, we
        # are just pulling things off and checking that nothing modified.
        #
        offset = const.SENTINEL_HEX_LEN + const.NONCE_CLIENT_HEX_LEN
        sentinel = self.handshake_ID[ : const.SENTINEL_HEX_LEN]
        nonce_client = self.handshake_ID[const.SENTINEL_HEX_LEN : offset].decode("hex")
        full_sentinel_hex = get_full_sentinel_hex(self.sentinel)

        if (sentinel != self.sentinel
            or nonce_client != self.nonce_client
            or full_sentinel_hex != self.full_sentinel_hex):
            print "initial info does not match"
            self.cm.remove_flow(self.flow_tuple)
            return

        try:
            uri_start = http_msg.index('GET /')
            uri_end = http_msg.index(' HTTP/1.1')
            cipher_uri = http_msg[uri_start + len('GET /') : uri_end]
            cipher_uri = cipher_uri.decode("hex")
            auth_plain_uri = self.rc4_handshake_c2d.update(cipher_uri)
            hash_offset = const.HTTPU_HEX_HASHLEN
            uri_offset = hash_offset + len(const.HTTPU_HASHSEP)
            plain_uri = auth_plain_uri[uri_offset:]
            test_uri = '%s%s%s' % (
                        self.encoder.digest(plain_uri), const.HTTPU_HASHSEP, plain_uri)

            if test_uri != auth_plain_uri:
                print "test and auth uris do not match"
                self.cm.remove_flow(self.flow_tuple)
                return

            if plain_uri != const.HTTPU_CLIENTHELLO:
                print "plain uri is not a client hello"
                self.cm.remove_flow(self.flow_tuple)
                return

            self.state = const_dp.STATE_4_UNI

        except ValueError:
            self.cm.remove_flow(self.flow_tuple)

    def handshake_hijacked(self, http_msg):
        """
        State 4:  Ready

        Forward http_msg to CT_DP
        """

        try:
            self.ctdp_src_sock.send(http_msg)
        except socket.error:
            print "Error: socket closed"
            self.cm.remove_flow(self.flow_tuple)

def make_padder(rsa_modulus_len):

    def CurveballRSAPadding(bytes, blockType):
        """
        When processing the PremasterSecret, reach inside the RSAKey class
        and replace the way it does PKCS1 padding, so that we create the
        sam padding that the client does.
        """

        padLength = (rsa_modulus_len - (len(bytes)+3))
        if blockType == 1: #Signature padding
            pad = [0xFF] * padLength
        elif blockType == 2: #Encryption padding
            pad = tlsCompat.createByteArraySequence([])
            while len(pad) < padLength:
                padincr = [b|0x1 for b in bytes]
                pad.extend(padincr)
            pad = pad[:padLength]
        else:
            raise AssertionError()

        #NOTE: To be proper, we should add [0,blockType].  However,
        #the zero is lost when the returned padding is converted
        #to a number, so we don't even bother with it.  Also,
        #adding it would cause a misalignment in verify()

        padding = tlsCompat.createByteArraySequence([blockType])
        padding.extend(pad)
        padding.extend([0])
        paddedBytes = padding + bytes
        # DEBUG and log_debug("Padded RSA block (len %d): %s"
        #                     % (len(paddedBytes),
        #                        binascii.hexlify(paddedBytes)))
        return paddedBytes

    return CurveballRSAPadding

# Borrowed from TLSlite implementation
class TLSConnectionState(object):

    def __init__(self):
        self.macContext = None
        self.encContext = None
        self.seqnum = 0

    def getSeqNumStr(self):
        w = tlslite.utils.codec.Writer(8)
        w.add(self.seqnum, 8)
        seqnumStr = bytesToString(w.bytes)
        self.seqnum += 1
        return seqnumStr

def getHMAC(app_data, mac_key, rec_no):
    """
    Create HMAC for record
    """
    temp = struct.pack('!QBBBBB', rec_no, 23, 3, 1,
                        (len(app_data)>>8) & 0xff,
                        len(app_data) & 0xff)
    hm = hmac.new(str(mac_key), digestmod = hashlib.sha1)       
    hm.update(temp)
    hm.update(app_data)
    hmac_data = hm.digest()
    return hmac_data            

def checkHMAC(plain_text, seqno, hmac_key):
        
    pad_len = ord(plain_text[- 1 : ])
    hmac_len = 20
    pad_data = plain_text[- (pad_len + 1) : - 1]
    hmac_data = plain_text[- (1 + pad_len + hmac_len) :- (1 + pad_len)]
    app_data = plain_text[ : - (1 + pad_len + hmac_len)]
       
    if len(pad_data) != pad_len:
        return False

    for index in range(0, len(pad_data)):
        if ord(pad_data[index]) != pad_len:
            return False
                
    if ((len(app_data) + len(hmac_data) + len(pad_data)+1) != len(plain_text)):
        return False

    temp = struct.pack('!QBBBBB', seqno, 23, 3, 1,
                        (len(app_data)>>8) & 0xff, 
                        len(app_data) & 0xff)
        
    hm = hmac.new(str(hmac_key), digestmod = hashlib.sha1)
    hm.update(temp)
    hm.update(app_data)
    sha1_app_data = hm.digest()
    
    if sha1_app_data != hmac_data:
        print 'Error: HMAC failure'
        print str(sha1_app_data).encode("hex")
        print str(hmac_data).encode("hex")
        return False

    return True

def getCorrectIV(cipher_text, decrypt_key, mac_key):
    """
    Although we have the right initialization vector, we didn't 
    decrypt the very first message that was encrypted: the finished
    message. So here we spoof the iv, knowing that the msg is 'G'
    """
        
    # Decrypt first record, assuming that iv is all zeros
    #
    zero_iv = bytearray(16)
    first_rec_hex = str(cipher_text).encode("hex")
    from_client_temp = createAES(decrypt_key, zero_iv)
    orig_plaintext = from_client_temp.decrypt(binascii.unhexlify(first_rec_hex)) 
                    
    # Construct expected first block
    # 
    app_data = 'G'
    hmac_data = getHMAC(app_data, mac_key, 1)
    new_plaintext = app_data + hmac_data
                    
    # xor the original block and the block we expect
    # to get the correct iv
    #
    orig_hex = str(orig_plaintext[:16]).encode("hex")
    new_hex = str(new_plaintext[:16]).encode("hex")
    correct_iv_hex = (''.join(hex( int(o,16) ^ int(n,16) )[2:] 
                        for o,n in zip(orig_hex, new_hex)))
    correct_iv = binascii.unhexlify(correct_iv_hex)
        
    return correct_iv

class TLSCryptoData(object):
    """
    A class to hold crypto data (keys, IV, cipher type)
    """
    def __init__(self):
        
        # These need to be filled in when we learn them
        #
        self.version = (0, 0)
        self.serverRecordHeaderLen = None
        self.clientVersion = (0, 0)
        self.clientRecordHeaderLen = None

        # Type is bytearray
        #
        self.sentinel = None
        self.sentinelLabel = None
        self.preMasterSecret = None
        self.clientRandom = None
        self.serverRandom = None
        self.cipherSuite = None
        self.serverCert = None
        self.serverCertType = None
        self.serverPublicKey = None

        # These are calculated by methods
        #
        self.macLength = None
        self.keyLength = None
        self.ivLength = None
        self.createCipherFunc = None
        self.createMACFunc = None

        self.clientMACBlock = None
        self.clientKeyBlock = None
        self.clientIVBlock = None
        self.serverMACBlock = None
        self.serverKeyBlock = None
        self.serverIVBlock = None
        
        # Used for spoofing client requests to DP
        # May not need all of these
        #
        self.clientMACBlockSpoofEnc = None
        self.clientKeyBlockSpoofEnc = None
        self.clientIVBlockSpoofEnc = None                
        self.clientMACBlockSpoofDec = None
        self.clientKeyBlockSpoofDec = None
        self.clientIVBlockSpoofDec = None
        self.clientMACBlockSpoofDecTemp = None
        self.clientKeyBlockSpoofDecTemp = None
        self.clientIVBlockSpoofDecTemp = None
        
        self.serverMACBlockSpoofEnc = None
        self.serverKeyBlockSpoofEnc = None
        self.serverIVBlockSpoofEnc = None
        self.serverMACBlockSpoofDec = None
        self.serverKeyBlockSpoofDec = None
        self.serverIVBlockSpoofDec = None
        self.serverMACBlockSpoofDecTemp = None
        self.serverKeyBlockSpoofDecTemp = None
        self.serverIVBlockSpoofDecTemp = None

    def calcMasterSecret(self):

        if self.version == (3,0):
            self.masterSecret = tlsMath.PRF_SSL(
                    self.preMasterSecret,
                    tlsCompat.concatArrays(self.clientRandom, self.serverRandom),
                    48)

        elif self.version in ((3,1), (3,2)):
            self.masterSecret = tlsMath.PRF(
                    self.preMasterSecret, "master secret",
                    tlsCompat.concatArrays(self.clientRandom, self.serverRandom),
                    48)
        else:
            raise AssertionError()
   
    def setCipherSuite(self, suite):
        self.cipherSuite = suite

        if self.cipherSuite in tlsConst.CipherSuite.aes128Suites:
            self.macLength = 20
            self.keyLength = 16
            self.ivLength = 16
            self.createCipherFunc = createAES
            return 0
        elif self.cipherSuite in tlsConst.CipherSuite.aes256Suites:
            self.macLength = 20
            self.keyLength = 32
            self.ivLength = 16         
            self.createCipherFunc = createAES
            return 0
        elif self.cipherSuite in tlsConst.CipherSuite.rc4Suites:
            self.macLength = 20
            self.keyLength = 16
            self.ivLength = 0
            self.createCipherFunc = createRC4
            return 0
        elif self.cipherSuite in tlsConst.CipherSuite.tripleDESSuites:
            self.macLength = 20
            self.keyLength = 24
            self.ivLength = 8
            self.createCipherFunc = createTripleDES
            return 0
        else:
            print ("ConnMon: AssertionError Unknown ciphersuite: %d (0x%x)"
                     % (self.cipherSuite, self.cipherSuite))
            return -1

    def calcSessionKeyData(self):
        settings = tlslite.HandshakeSettings.HandshakeSettings()
        settings._filter()
        implementations = settings.cipherImplementations

        if self.version == (3,0):
            createMACFunc = tlsMath.MAC_SSL
        elif self.version in ((3,1), (3,2)):
            createMACFunc = tlsHmac.HMAC

        outputLength = (
                (self.macLength*2) + (self.keyLength*2) + (self.ivLength*2))

        # Calculate Keying Material from Master Secret
        #
        if self.version == (3,0):
            keyBlock = tlsMath.PRF_SSL(self.masterSecret,
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofEnc = tlsMath.PRF_SSL(self.masterSecret,
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofDec = tlsMath.PRF_SSL(self.masterSecret,
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofDecTemp = tlsMath.PRF_SSL(self.masterSecret,
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength) 
                        
        elif self.version in ((3,1), (3,2)):
            keyBlock = tlsMath.PRF(self.masterSecret, "key expansion",
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofEnc = tlsMath.PRF(self.masterSecret, "key expansion",
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofDec = tlsMath.PRF(self.masterSecret, "key expansion",
                    tlsCompat.concatArrays(self.serverRandom, self.clientRandom),
                    outputLength)
            keyBlockSpoofDecTemp = tlsMath.PRF(self.masterSecret, "key expansion",
                    tlsCompat.concatArrays(self.serverRandom,  self.clientRandom),
                    outputLength)            
        else:
            raise AssertionError()

        # Slice up Keying Material
        #
        p = tlsParser(keyBlock)
        self.clientMACBlock = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.serverMACBlock = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.clientKeyBlock = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.serverKeyBlock = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.clientIVBlock  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        self.serverIVBlock  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        
        p = tlsParser(keyBlockSpoofEnc)
        self.clientMACBlockSpoofEnc = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.serverMACBlockSpoofEnc = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.clientKeyBlockSpoofEnc = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.serverKeyBlockSpoofEnc = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.clientIVBlockSpoofEnc  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        self.serverIVBlockSpoofEnc  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
              
        p = tlsParser(keyBlockSpoofDec)
        self.clientMACBlockSpoofDec = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.serverMACBlockSpoofDec = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.clientKeyBlockSpoofDec = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.serverKeyBlockSpoofDec = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.clientIVBlockSpoofDec  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        self.serverIVBlockSpoofDec  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
 
        p = tlsParser(keyBlockSpoofDecTemp)
        self.clientMACBlockSpoofDecTemp = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.serverMACBlockSpoofDecTemp = tlsCompat.bytesToString(p.getFixBytes(self.macLength))
        self.clientKeyBlockSpoofDecTemp = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.serverKeyBlockSpoofDecTemp = tlsCompat.bytesToString(p.getFixBytes(self.keyLength))
        self.clientIVBlockSpoofDecTemp  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        self.serverIVBlockSpoofDecTemp  = tlsCompat.bytesToString(p.getFixBytes(self.ivLength))
        
        if self.version == (3,2) and self.ivLength:
            # Choose fixedIVBlock for TLS 1.1 (this is encrypted with the CBC
            # residue to create the IV for each sent block)
            #
            self.fixedIVBlock = getRandomBytes(self.ivLength)
  
    def compute_pms(self):

        hash_input = (
                self.clientRandom + self.serverRandom +
                array.array('B', '\x00' * 
                            TLSFlowMonitor.CB_SENTINEL_LABEL_BYTES))

        h = hashlib.sha512()
        h.update(hash_input)

        # premaster secret begins with two bytes containing the
        # version number --- Curveball clients use (3,1)
        #
        self.preMasterSecret = array.array(
                'B', bytearray('\x03\x01') + h.digest()[0:46])
        
    def check_client_pms(self, pms_from_client):
        """
        Calculate what we expect the PMS should be, and compare to
        what we read from the client
        """
        try:
            hash_input = (
                    self.clientRandom + self.serverRandom +
                    array.array('B', '\x00' * 
                                TLSFlowMonitor.CB_SENTINEL_LABEL_BYTES))

            h = hashlib.sha512()
            h.update(hash_input)

            # premaster secret begins with two bytes containing the
            # version number --- Curveball clients use (3,1)
            #
            self.preMasterSecret = array.array(
                    'B', bytearray('\x03\x01') + h.digest()[0:46])

            encryptedPMS = self.serverPublicKey.encrypt(self.preMasterSecret)

            # Convert from an array to a long
            #
            my_pms_cyphertext = 0
            for b in encryptedPMS:
                my_pms_cyphertext = ((my_pms_cyphertext<<8)|b)

            return (my_pms_cyphertext == pms_from_client)

        except Exception as e:
            return False

    def handle_server_finished(self, r):
        # I would like to say the following, but it appears that, at
        # least some times, the body of the server-finished message is
        # encrypted, and the parser isn't prepared for that.
        #
        # f = tlsFinished(self.version).parse(r.tcParseStream)
        # self.serverIVBlock = tlsCompat.bytesToString(finished.verify_data[-self.ivLength:])

        self.serverIVBlock = r.tcParseStream.bytes[-self.ivLength:]
        DEBUG and log_debug("Setting server IV to %s"
                            % binascii.hexlify(self.serverIVBlock))

    def handle_server_certificate(self, r):
        # would like to do this:
        # self.certificate = tlsCertificate(self.certificate_type).parse(r)
        # but it does not retain the X509 structures it finds along
        # the way, and we want the public key (from one of them).  So
        # we take the contents of tlsCertificate.parse

        # where does certificate_type come from?  You would think it would
        # come from the thing being parsed, but it actually comes from
        # the s = ServerHello(...)/s.parse(p)/s.certificate_type

        try:
            self.certificate = tlsCertificate(self.serverCertType).parse(
                    r.tcParseStream)

        except SyntaxError:
            # tlslite uses SyntaxError exception to indicate badly-formed TLS
            raise ValueError("tlslite cannot parse the certificate")

        if not isinstance(self.certificate.certChain, tlsX509Chain):
            # FIXME: don't know how to deal with other certchain
            raise ValueError("Server certificate not x509")

        # this is a subclass of tlslite.utils.RSAKey.RSAKey:
        certChain = self.certificate.certChain
        if(not certChain) or certChain.getNumCerts() == 0:
            raise ValueError("server certificate message with no certificates")

        else:
            self.serverPublicKey = certChain.getEndEntityPublicKey()

            rsa_modulus_len = tlslite.utils.cryptomath.numBytes(
                    self.serverPublicKey.n)

            self.serverPublicKey._addPKCS1Padding = make_padder(
                    rsa_modulus_len)

            log_warn("--------Not yet verifying X509 certificate chain-------")

        return self

def tlsRecordRecv(cm, tuple, reassembler, header_len, ssl_version):
    """
    Much of this code is modeled on tlslite's
    TLSRecordLayer._getNextRecord method
    """
        
    # Not enough data available to read a header yet
    #
    if reassembler.len() < header_len:
        return (None, None)

    # I don't think the tlslite documentation makes it clear that
    # the argument to tlsTc.Parser() needs to be a bytearray (inside
    # the tlslite code it treats elements of the array as
    # integers, not chars).
    #
    bytes = bytearray(reassembler.peek(header_len))

    try:
        if ssl_version == (3, 0):
            rec = tlsTm.RecordHeader2().parse(tlsTc.Parser(bytes))
        elif ssl_version in ((3,1), (3,2)):
            rec = tlsTm.RecordHeader3().parse(tlsTc.Parser(bytes))
        else:
            print("wrong ssl_version (%s)" % str(ssl_version))
            cm.remove_flow(tuple)
            return (None, None)

    except SyntaxError:
        print("Malformed TLS record")
        cm.remove_flow(tuple)
        return (None, None)

    # Protocol defines maximum length to be 2^14 (16384)
    # tlslite.TLSRecordLayer._getNextRecord() uses 18432 here, for
    # some reason
    #
    if rec.length > 18432:
        print("SSL Record overflow")
        cm.remove_flow(tuple)
        return (None, None)

    # Don't have the full record yet
    #
    if rec.length + header_len > reassembler.len():
        return (None, None)

    # Header we've already peeked at
    #
    header = reassembler.recv(header_len, commit=True, raw=False)

    # Another view into the data, suitable for tlslite parse routines
    #
    rec.tcParseStream = tlsTc.Parser(
            bytearray(reassembler.recv(rec.length, commit=True, raw=True)))

    return (rec, header)

def sslIdentify(reassembler):
    """
    Figure out if correspondent is speaking SSL3 or SSL2, and
    corresponding header sizes.
    """

    if reassembler.len() < 1:
        return (None, None)
    else:
        # slavishly copied from
        # Tlslite.TLSRecordLayer._getNextRecord() --- I don't see
        # where the val == 128/2 byte header comes from.  Maybe we
        # don't even want to talk to hosts that use such records.
        #
        bytes = reassembler.peek(1)
        val = struct.unpack('B', bytes)[0]
        # XXXX FIXME --- this might be (3,0)
        # fix is to convert over to using tlslite here
        if val in tlsConst.ContentType.all:
            return ((3, 1), 5)

        elif val == 128:
            return ((2, 0), 2)
        else:
            print("Unknown SSL version: %d" % int(val))
            return (None, None)

def updateCBC(r, dir, crypto):
    """
    When we see encrypted records, keep track of the last block
    for use in future decryption of CBC.
    """
    subtype = r.tcParseStream.bytes[0]
    if(r.type ==  tlsConst.ContentType.application_data
        or (r.type ==  tlsConst.ContentType.handshake
            and tlsHandshakeFinished(subtype))):

        # This is an encrypted record, remember last cipher block
        if dir == "C->S":
            crypto.clientIVBlock = r.tcParseStream.bytes[-crypto.ivLength:]
        else:
            crypto.serverIVBlock = r.tcParseStream.bytes[-crypto.ivLength:]

class TLSUnknownFlowMonitor(FlowMonitor):

    def __init__(self, tupl, cm, syn_options, isn, dr2dp):
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.recv_buf = ''
        self.dr2dp = dr2dp
        self.crypto = TLSCryptoData()

    def traffic_to_client(self, pkt):

        # Don't forward on reverse packets here, only store them
        #   Will get forwarded on in TLSBiFlowMonitor
        #
        print "TLSUnknownFlowMonitor: got reverse traffic"
        self.reassembler_reverse.add_pkt(pkt.clone())
        self.dr2dp.send_to_dr(str(pkt))

    def traffic_from_client(self, pkt):
        """
        Process packets coming from the client
        """

        self.dr2dp.send_to_dr(str(pkt.clone()))
        
        # Deal with acks  
        #
        if pkt.get_payload_len() == 0:
            return
        
        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            print "Detected FIN or RST"
            self.cm.remove_flow(self.flow_tuple)
            return

        self.reassembler_forward.add_pkt(pkt)       
       
        if self.crypto.clientVersion == (0, 0):
            (self.crypto.clientVersion,
             self.crypto.clientRecordHeaderLen) = sslIdentify(
                    self.reassembler_forward)
        
        if self.crypto.clientVersion == (0, 0):
            self.cm.remove_flow(self.flow_tuple)
            return

        tuple = pkt.get_tuple()
        (rec, header)= tlsRecordRecv(
                self.cm, tuple, self.reassembler_forward, 
                self.crypto.clientRecordHeaderLen, 
                self.crypto.clientVersion)

        if rec == None:
            return

        subtype = rec.tcParseStream.get(1)
        if (rec.type == tlsConst.ContentType.handshake
            and (subtype == tlsConst.HandshakeType.client_hello)):
                clientRandom = self.clientHello(rec)
                if clientRandom != -1:
                    self.tunnel_type = self.getTLSTunnelType(clientRandom)
                else:
                    self.cm.remove_flow(self.flow_tuple)
                    
    def clientHello(self, rec):
      
        # Bump the buffer pointer up to the start of the sentinel
        ch = tlsTm.ClientHello().parse(rec.tcParseStream)
        sentinel = ch.random
        self.crypto.clientVersion = ch.client_version
        self.crypto.clientRandom = array.array('B', [b for b in sentinel])

        cipher_suites = array.array('H', ch.cipher_suites)
        hexsent = binascii.hexlify(sentinel[4:12])
        if (hexsent in FlowMonitor.sentinels or hexsent.startswith('deadbeef')):
            # CT_DP2 will use a callback to get at this
            # TLSUni/BiFlowMonitor instance, in order to ask it for
            # the sentinel.  We'll also be using it to calculate
            # the premaster secret we expect from the client
            #
            # FIXME this includes more than just the sentinel
            #
            self.crypto.sentinel = sentinel
            if hexsent.startswith('deadbeef'):
                self.crypto.sentinelLabel = 'deadbeef0000000000000000000000000000000000000000'
            else:
                self.crypto.sentinelLabel = self.sentinels[hexsent]
            self.state = 'ClientSentinelSeen'
        
            # This must be set before updateCBC gets called.
            # Because we only support AES128 and AES256, this is 
            # always 16 bytes
            #
            self.crypto.ivLength = 16       
            updateCBC(rec, 'C->S', self.crypto)
        
            return ch.random
        
        else:
            return -1
           
    
    def getTLSTunnelType(self, clientRandom):
        """
        XOR 1st bit of last byte of client random with 1st bit of
        last byte of sentinel label
        """
        
        tunnel_type_byte = ord(clientRandom[-1:])

        # sentinelLabel is stored as hex so need to take last 2 char and unhex
        #        
        sentinel_label_byte = ord(
                binascii.unhexlify(self.crypto.sentinelLabel[-2:]))
        decode_byte = tunnel_type_byte ^ sentinel_label_byte
        
        #print "TunnelTypeByte"
        #print bin(tunnel_type_byte)
        #print bin(sentinel_label_byte)  
        #print bin(decode_byte)
        #print self.crypto.sentinelLabel

        # And with byte = 1 to check whether 1st bit is set
        #
        if (decode_byte & 1) != 0:
            tunnel_type_bit = 1
        else:
            tunnel_type_bit = 0
              
        if tunnel_type_bit == 0:
            return const.CREATE_TLS_BI_TUNNEL
        elif tunnel_type_bit == 1:
            return const.CREATE_TLS_UNI_TUNNEL           
        else:
            # This case should never happen: either the bit was 0 or 1
            #
            self.cm.remove_flow(self.flow_tuple)        
            return const.UNKNOWN_TUNNEL


class TLSFlowMonitor(FlowMonitor):
    """
    Handle TLS flows
    """

    # length in bytes of the encrypted premaster secret for RSA
    PMS_LENGTH = 48
    PMS_ENCRYPTED_LENGTHS = (64, 128, 256, 512, 1024, 2048)
    CB_SENTINEL_LABEL_BYTES = 24


    def __init__(self, old_flow_mon, dr2dp):

        tupl          = old_flow_mon.flow_tuple
        cm            = old_flow_mon.cm
        syn_options   = old_flow_mon.syn_options
        isn           = old_flow_mon.isn
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.dr2dp = old_flow_mon.dr2dp
        self.reassembler_forward = old_flow_mon.reassembler_forward
        self.reassembler_reverse = old_flow_mon.reassembler_reverse
        self.recv_buf = old_flow_mon.recv_buf
        self.crypto = old_flow_mon.crypto
        self.state = old_flow_mon.state
        self.tunnel_type = const.TLS_BI_TUNNEL

        self.client_addr = None
        self.client_port = None
        self.client_data_records = 0
        self.from_client_decrypt_temp = None
        
    def handshake(self, pkt):
        """
        Follow the TLS handshake record by record,
        once we finish the last handshake record, prepare
        to send the next packet with a seq number >= that last
        record on to hijack

        How the state machine works in symmetric mode:
        State: Init
          client->server: ClientHello(sentinel||flowid); State = ClientSentinelSeen
                          [keep track of sentinel, figure out sentinel_label]
        State: ClientSentinelSeen
          server->client: ServerHello(some bits)
                          [keep track of certificate-type --- if not
                           x509, probably punt at this point.]
          server->client: server-certificate
                          [extract public key from certificate]
          server->client: ServerHelloDone
          client->server: ClientKeyExchange(premaster secret)
                          [verify that premaster secret is appropriate for
                           this client using this sentinel ---
                           if yes: state = ClientPremasterSeen
                           if no: state = PassThrough]
        State: ClientPremasterSeen:
          client->server: ChangeCipherSpec
          client->server: encrypted & authenticated Finished message
          server->client: ChangeCipherSpec; State = WaitingForClientData
        State: PassThrough
          we don't do anything, we just copy traffic back and forth
        State: WaitForClientData
          client->server: handshake finished
          client->server: ApplicationData record; State = hijacked
          client->server: anything; pass data through

        in all cases we pass the data through to the recipient, until we
        get to state==hijacked
        """

        if self.client_addr == None and pkt.get_dport() == 443:
            self.client_addr = pkt.get_src()
            self.client_port = pkt.get_sport()

        # Deal with acks
        #
        if pkt.get_payload_len() == 0:
            self.dr2dp.send_to_dr(str(pkt))
            return

        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        if pkt.get_sport() == 443:
            self.handshake_server_to_client(pkt)
        else:
            self.handshake_client_to_server(pkt)

    def _serverHello(self, r):
        """
        Process a server_hello message
        """
        try:
            sh = tlsTm.ServerHello().parse(r.tcParseStream)
            self.crypto.serverCertType = sh.certificate_type
            self.crypto.version = sh.server_version
            self.crypto.serverRandom = array.array(
                    'B', [b for b in sh.random])
            if self.crypto.setCipherSuite(sh.cipher_suite) == -1:
                self.cm.remove_flow(self.flow_tuple)
                
        except SyntaxError:
            # tlslite signals parse-errors of the SSL stream using
            # a SyntaxError exception
            log_error("Malformed ServerHello message")
            self.state = 'PassThrough'

    def _serverChangeCipherSpec(self):
        """
        Process a server change_cipher_spec message
        """
        if self.state == 'ClientPremasterSeen':
            self.crypto.calcMasterSecret()
            self.crypto.calcSessionKeyData()       
            self.state = 'WaitingForClientData'
        else:
            self.state = 'PassThrough'

    def _serverMessage(self, r):
        """
        Do the work of actually processing messages
        """
        send_pkt = True

        try:
            if r.type == tlsConst.ContentType.handshake:
                subtype = r.tcParseStream.get(1)

                if subtype == tlsConst.HandshakeType.server_hello:
                    self._serverHello(r)
                    
                elif subtype == tlsConst.HandshakeType.certificate:
                    self.crypto.handle_server_certificate(r)
               
                elif tlsHandshakeFinished(subtype):
                    self.crypto.handle_server_finished(r)

            elif r.type == tlsConst.ContentType.change_cipher_spec:
                # Server is now happy with the client!  Now we can hijack!
                self._serverChangeCipherSpec()
            
            elif r.type == tlsConst.ContentType.application_data:
                if self.state == 'Hijacked':
                    send_pkt = False
            else:
                DEBUG and log_debug("S->C: some other message type: %d" % r.type)
        
        except AssertionError as e:
            self.state = 'PassThrough'
            send_pkt = True

        except ValueError as e:
            self.state = 'PassThrough'
            send_pkt = True

        return send_pkt

    def handshake_server_to_client(self, pkt):
        """
        Monitor the TLS server's end of the handshake process.

        While the handshake is going on, the DP serves as a passive
        conduit of packets between the DH and the client.  Partial
        packets are sent on their way before being processed.
        """
        self.reassembler_reverse.add_pkt(pkt)

        if self.crypto.version == (0, 0):
            (self.crypto.version, self.crypto.serverRecordHeaderLen
                    ) = sslIdentify(self.reassembler_reverse)
        
        # Not enough data available to identify the version
        #
        if self.crypto.version == (0, 0):
            self.dr2dp.send_to_dr(str(pkt))
            return

        if self.state != 'Hijacked':
            self.dr2dp.send_to_dr(str(pkt))

        # Note that loop also exits when we run out of input
        #
        while self.state != 'Hijacked':
            (rec, header) = tlsRecordRecv(
                    self.cm,
                    self.flow_tuple,
                    self.reassembler_reverse,
                    self.crypto.serverRecordHeaderLen,
                    self.crypto.version)
            
            if rec == None:
                return

            self._serverMessage(rec)

    def clientKeyExchange(self, rec, pkt):
        tls_handshake_data_len = rec.tcParseStream.get(3)

        # See Eric Rescorla, "SSL and TLS: designing and building
        # secure systems", p 79 (discussion of ClientKeyExchange
        # message).  Basically, this is a little unpredictable.
        #
        # If the server we're talking to is version 3.0,
        # there's no length, there's just the encrypted premaster
        # secret (length determined by size of server key, and
        # deducible from the length of the handshake data).
        #
        # If server version is 3.1 or 3.2, then 2B length field is
        # followed by encrypted premaster secret.  Note that even though
        # it's the client composing the message, it has to conform
        # to the version chosen by the server.
        # Except our client does not do this --- there doesn't
        # appear to be a length field in what our client sends,
        # even though the server version is one of the TLS versions

        if tls_handshake_data_len in TLSFlowMonitor.PMS_ENCRYPTED_LENGTHS:
           
            # In ssl3.0, this is normal
            #
            if not self.crypto.version == (3,0):
                log_warn(("C->S: don't know that server is (3,0) but "
                          + "handshake data is exact blocklen: %d" )
                         % tls_handshake_data_len)
                
            pmslen = tls_handshake_data_len
       
        elif self.crypto.version in ((3,1), (3,2), (3,3)):
            
            length = rec.tcParseStream.get(2)
            if length not in TLSFlowMonitor.PMS_ENCRYPTED_LENGTHS:
                log_warn("C->S: Client looks like it's using "
                         + "SSL 3.0 premaster secret length non-encoding")

            pmslen = length
        
        else:
            # Not enough information to complete handshake
            #
            return False

        # FIXME: in asymmetric mode, we won't have seen the server's
        # selection of the cipher, and thus won't be certain of the
        # pmslen until we've found one that works.  Fortunately, there
        # are only a few candidates to try.
        #    
        encryptedPMS = rec.tcParseStream.get(pmslen)
        return self.crypto.check_client_pms(encryptedPMS)

    def handshake_client_to_server_state_machine(self, rec, pkt, pkt_sent):
        """
        Helper routine for handshake_client_to_server
        """
                           
        # We have a tls_record (rec), process it according to the state
        # we're in
        if not pkt_sent:
            self.dr2dp.send_to_dr(str(pkt))

        subtype = rec.tcParseStream.get(1)

        if (self.state == 'ClientSentinelSeen'
            and rec.type == tlsConst.ContentType.handshake):

            if(subtype == tlsConst.HandshakeType.client_key_exchange):
                
                if self.clientKeyExchange(rec, pkt):
                    self.state = 'ClientPremasterSeen'
                else:
                    self.state = 'PassThrough'
                    
        elif self.state == 'ClientPremasterSeen':

            # This record is encrypted, and the encryption seems to
            # cover the message subtype
            if tlsHandshakeFinished(subtype):
                # FIXME: if we ever do a stream cipher, we'll have to
                # pass this ciphertext through it.
                DEBUG and log_debug("Encrypted finished subtype? 0x%x"
                                    % subtype)
                            
        elif (self.state == 'WaitingForClientData'):
            
            if rec.type == tlsConst.ContentType.application_data:
            
                # the client bundles up its get in several records
                self.client_data_records += 1
                
                if (self.check_record_hmac(rec, self.client_data_records) == False):
                     self.dr2dp.send_to_dr(str(pkt))
                     self.cm.remove_flow(self.flow_tuple)
                     return
               
                if self.client_data_records <2:
                    return
                
                self.state = 'Hijacked'
                                  
                try:
                    self.init_hijack(pkt, self.reassembler_forward.seq-1)
                except Exception as e:
                    log_error("Exception trying to init hijack: %s" % str(e))
                    self.state = 'PassThrough'

    def check_record_hmac(self, r, seqno):
        cipher_text = copy.copy(r.tcParseStream.bytes[:])
        
        if seqno == 1:
            decrypt_key = self.crypto.clientKeyBlockSpoofDecTemp
            correct_iv_rec1 = getCorrectIV(cipher_text, 
                                           self.crypto.clientKeyBlockSpoofDec,
                                           self.crypto.clientMACBlockSpoofDec)
            self.from_client_decrypt_temp = createAES(decrypt_key, correct_iv_rec1)   
        
        plain_text = self.from_client_decrypt_temp.decrypt(cipher_text)  
        hmac_key = self.crypto.clientMACBlockSpoofDecTemp
        if (checkHMAC(plain_text, seqno, hmac_key) == False):
            return False
        
        return True

    def handshake_client_to_server(self, pkt):

        self.reassembler_forward.add_pkt(pkt)

        pkt_sent = False
        while self.state != 'Hijacked':
            # NOTE: loop exits when there are no complete TLS records
            # in the reassembly queue OR the handshake
            # packet-processing decides we've entered the hijacked
            # state.

            (rec, header) = tlsRecordRecv(
                    self.cm,
                    self.flow_tuple,
                    self.reassembler_forward,
                    self.crypto.clientRecordHeaderLen,
                    self.crypto.clientVersion)
            
            if rec == None:
                # not enough data accumulated in reassembler yet
                if not pkt_sent:
                    self.dr2dp.send_to_dr(str(pkt))
                    pkt_sent = True
                return 
            else:
                updateCBC(rec, 'C->S', self.crypto)
                if self.state == 'PassThrough':
                    if not pkt_sent:
                        self.dr2dp.send_to_dr(str(pkt))
                        pkt_sent = True
                    return 
                else:
                    self.handshake_client_to_server_state_machine(rec, pkt, pkt_sent)
                    # handshake_client_to_server_state_machine will send the pkt
                    # if it hasn't already been sent, so mark pkt_sent as True
                    pkt_sent = True

    def __str__(self):
        return """TLSFlowMonitor %d
client: %s port %d
state: %s
sentinel: %s
sentinel_label: %s
reassembler_forward.len: %d
reassembler_reverse.len: %d
""" % (id(self),
       socket.inet_ntoa(self.client_addr), self.client_port,
       self.state,
       binascii.b2a_hex(self.crypto.sentinel),
       self.crypto.sentinelLabel,
       self.reassembler_forward.len(),
       self.reassembler_reverse.len())

class TLSUniFlowMonitor(FlowMonitor):
    """
    TLSUniFlowMonitor watches the data on a TLS flow --- looking for
    the steps of the TLS handshake, and looking for the components
    that represent the Curveball TLS Uni handshake.  Once the
    handshake arrives, the TLSUniFlowMonitor rewrites the connection.
    """
    # length in bytes of the encrypted premaster secret for RSA
    #
    PMS_LENGTH = 48
    PMS_ENCRYPTED_LENGTHS = (64, 128, 256, 512, 1024, 2048)
    CB_SENTINEL_LABEL_BYTES = 24

    def __init__(self, old_flow_mon, dr2dp, tls_uni_ct_dp):

        tupl          = old_flow_mon.flow_tuple
        cm            = old_flow_mon.cm
        syn_options   = old_flow_mon.syn_options
        isn           = old_flow_mon.isn
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.dr2dp = old_flow_mon.dr2dp
        self.reassembler_forward = old_flow_mon.reassembler_forward
        self.recv_buf = old_flow_mon.recv_buf
        self.crypto = old_flow_mon.crypto
        self.state = old_flow_mon.state
        self.tunnel_type = const.TLS_UNI_TUNNEL
        
        self.host = str(socket.inet_ntoa(self.flow_tuple[2]))
        self.client_addr = None
        self.client_port = None
        self.client_data_records = 0 
        self.cipher_text1 = None

        # TLS crypto state
        #
        self.from_client_dec = None
        self.from_client_enc = None 

        # We only support (3,1)
        #
        self.crypto.version = (3, 1)
        self.crypto.serverRecordHeaderLen = 5
        self.crypto.serverCertType = 0

        # Mole variables
        #
        self.mole_created = False
        self.mole = None
        self.tls_mole_encoder = None 
        self.tls_uni_ct_dp = tls_uni_ct_dp
        self.ctdp_src_sock = None
        self.reset_mole_state = False
        
        self.welcome_req = ("GET /" + const.TLSUNI_CURVEBALLHELLO 
                            + " HTTP/1.1\r\nUser-Agent:"
                            + "EKRClient\r\nHost: decoy:443\r\n\r\n") 

    def handshake(self, pkt):
        """
        Follow the TLS handshake record by record
        """

        if self.client_addr == None and pkt.get_dport() == 443:
            self.client_addr = pkt.get_src()
            self.client_port = pkt.get_sport()

        # Deal with acks  
        #
        if pkt.get_payload_len() == 0:
            self.dr2dp.send_to_dr(str(pkt))
            return
        
        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            print "Detected FIN or RST"
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return
        
        if pkt.get_sport() == 443:
            self.dr2dp.send_to_dr(str(pkt))
        else:
            self.client_to_server(pkt)

    def client_to_server(self, pkt):

        self.reassembler_forward.add_pkt(pkt)

        if self.state != 'WaitingForClientData':
            self.dr2dp.send_to_dr(str(pkt.clone()))

        elif (self.state == 'WaitingForClientData' and
              self.client_data_records <= 1):
            self.dr2dp.send_to_dr(str(pkt.clone()))

        elif self.state == 'WaitingForClientData' and self.mole_created == True:
            self.use_mole_tunnel(pkt.get_seq(), pkt.clone())

        # Loop through records
        #        
        while True:

            (rec, header) = tlsRecordRecv(
                    self.cm, self.flow_tuple, self.reassembler_forward,
                    self.crypto.clientRecordHeaderLen,
                    self.crypto.clientVersion)

            if rec == None:
                return

            updateCBC(rec, 'C->S', self.crypto)
            subtype = rec.tcParseStream.get(1)
            cipher_text = copy.copy(rec.tcParseStream.bytes[:])
            header_type_hex = str(header).encode("hex")[0:2]

            if (self.state == 'ClientSentinelSeen' and
                rec.type == tlsConst.ContentType.handshake):
                if subtype == tlsConst.HandshakeType.client_key_exchange:
                    self.state = 'ClientPremasterSeen'

            elif self.state == 'ClientPremasterSeen':
                if int(header_type_hex) == 16:
                    self.state = 'WaitingForClientData'

            elif self.state == 'WaitingForClientData':

                if rec.type == tlsConst.ContentType.application_data:
                    self.client_data_records += 1

                    if self.client_data_records <= 2:
                        self.process_app_data_rec_1_2(cipher_text)
                    else:
                        self.process_app_data_rec_3_plus(cipher_text, pkt)

    def process_app_data_rec_1_2(self, cipher_text):
        """
        Process 1st and 2nd application data records
        """

        if self.client_data_records == 1:
            self.cipher_text1 = cipher_text

        elif self.client_data_records == 2:
            cipher_text2 = cipher_text

            # At this point we have all the information we need
            #  to obtain the encryption and decryption keys
            #
            self.crypto.serverRandom = self.decode_stencil(cipher_text2)
            self.crypto.compute_pms()
            self.crypto.calcMasterSecret()
            self.crypto.calcSessionKeyData()

            # Create encryption state
            #    
            correct_iv_rec1 = getCorrectIV(self.cipher_text1,
                                           self.crypto.clientKeyBlockSpoofDec,
                                           self.crypto.clientMACBlockSpoofDec)

            encrypt_key = self.crypto.clientKeyBlockSpoofEnc
            hmac_key = self.crypto.clientMACBlockSpoofEnc
            self.from_client_enc = self.create_cipher_state(
                    encrypt_key, correct_iv_rec1, hmac_key, seq_no=1)

            # Decrypt first 2 records and check hmacs. 
            #   We don't have the keys until we receive the 
            #   first 2 records, so we can't check the hmac
            #   of the 1st record until now.
            #
            # TODO: This could be a security vulnerability
            #
            decrypt_key = self.crypto.clientKeyBlockSpoofDecTemp
            hmac_key = self.crypto.clientMACBlockSpoofDecTemp
            from_client_temp = createAES(decrypt_key, correct_iv_rec1)
            plain_text1 = from_client_temp.decrypt(self.cipher_text1)
            plain_text2 = from_client_temp.decrypt(cipher_text2)

            if (checkHMAC(plain_text1, 1, hmac_key) == False or
                checkHMAC(plain_text2, 2, hmac_key) == False):
                self.cm.remove_flow(self.flow_tuple)
                return

            # Decrypted first 2 records to know what they are. 
            #   Now encrypt then decrypt to get into right 
            #   encryption and decryption state
            #
            decrypt_key = self.crypto.clientKeyBlockSpoofDec
            self.from_client_dec = createAES(decrypt_key, correct_iv_rec1)
            self.from_client_enc.encrypt_data_record(plain_text1)
            self.from_client_enc.encrypt_data_record(plain_text2)
            self.from_client_dec.decrypt(self.cipher_text1)
            self.from_client_dec.decrypt(cipher_text2)

    def process_app_data_rec_3_plus(self, cipher_text, pkt):
        """
        Process 3rd and later application data records

        pkt is only used to create the mole tunnel, or to
        bail out gracefully if hmac or socket fail
        """

        # Create Mole
        #
        if self.mole == None:
            pkt_clone = pkt.clone()
            pkt_seq_no = pkt_clone.get_seq()
            self.create_mole_tunnel(pkt_seq_no)
            self.use_mole_tunnel(pkt_seq_no, pkt_clone)
            self.mole_created = True

        # Determine length of padding and length of data
        #
        if self.from_client_dec == None:
            print "Error: client decrypt object not initialized"
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        plain_text = self.from_client_dec.decrypt(cipher_text)
        hmac_key = self.crypto.clientMACBlockSpoofEnc
        rec_no = self.client_data_records
        if (checkHMAC(plain_text, rec_no, hmac_key) == False):
            print "Error: hmac failed"
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

               
        pad_len = ord(plain_text[- 1 : ])
        hmac_len = self.crypto.macLength
        data_len = len(plain_text) - hmac_len - pad_len - 1
        data = plain_text[:data_len]

        # Forward on data from record to CT_DP
        #
        try:
            self.ctdp_src_sock.send(data)
        except socket.error:
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)

    def decode_stencil(self, cipher_text):
        """
        Pull off ciphersuite and server random from the stencil
        """

        # TODO: Not handling deadbeef case here
        # 
        stencil_key = self.crypto.sentinelLabel[-32:]
        decoder = EncryptedStencilDecoder(stencil_key)

        [cipherSuite, serverRandom] = \
                decoder.decode_with_ciphersuite(str(cipher_text))

        serverRandom = bytearray(serverRandom)
        newServerRandom = array.array('B',[b for b in serverRandom])
        self.crypto.cipherSuite = cipherSuite
        if self.crypto.setCipherSuite(self.crypto.cipherSuite) == -1:
            self.cm.remove_flow(self.flow_tuple)

        return newServerRandom

    def create_cipher_state(self, key_block, iv, mac, seq_no):

        cipher_state = cb.cssl.cssl.CurveballTLS()
        cipher_state.cipher_set(self.crypto.createCipherFunc(key_block, iv),iv)
        cipher_state.hmac_key_set(mac)
        cipher_state.sequence_number_set(seq_no)
        return cipher_state

    def create_mole_tunnel(self, tcp_seq_no):
        """
        This tunnel should only be created after the TLSUNI handshake
        has completed.
        """

        # Open a socket to the TLS_UNI_CT_DP
        #
        try:
            self.ctdp_src_sock = socket.socket()
            self.ctdp_src_sock.connect(
                    ('localhost', const.TLS_UNI_CT_DP_PORT))
            self.ctdp_src_sock.setblocking( False )
        except socket.error:
            self.ctdp_src_sock = None

        # Create the mole tunnel object and pass to the TLS_UNI_CT_DP
        #
        self.tls_mole_encoder = HttpMoleCryptoEncoder(
                self.host, self.crypto.sentinelLabel)

        # Spoof record
        #
        self.mole = TLSMoleTunnelDp(
                self.tls_mole_encoder, self.from_client_enc, 
                tcp_seq_no, self.welcome_req)

        self.tls_uni_ct_dp.setMole(self.mole)

        # Set up buffering for mole tunnel
        #
        self.partition_size = 0x200000
        self.highest_partition = 0xffffffff / self.partition_size
        self.max_partition = tcp_seq_no / self.partition_size
        if self.max_partition == 0:
            self.min_partition = self.highest_partition
        else:
            self.min_partition = self.max_partition - 1
        self.gen_wrap = 0   

    def use_mole_tunnel(self, seq_no, pkt):

        # Use a heuristic-based state machine to determine the
        # "unwrapped" sequence number, based on the original sequence number.
        # We assume that the sequence numbers are seen in a semi-sequential
        # order such that if we use a window of osize 0x1000000 (or any other
        # suitable value) that evenly divides 2^32), then we can can partition
        # the 32-bit space into partitions of this window size such:
        #
        # a) two consecutively observed sequence numbers must either be
        # within the same partition, or two adjacent partition
        #
        # b) if the highest sequence number observed is in partition N, then
        # the next observation must be in partition N or N-1, N, or N+1 (all
        # modulo the number of partitions).
        #
        # Property b) means that we don't have to move forward constantly,
        # but there is a limit to how far "backward" we can go once we have
        # seen any sequence number in a given partition.
        #
        # We can use properties a) and b) together to determine when a wrap
        # has happened, and add the proper amount to the "effective" sequence
        # number.

        # figure out which partition we are in, and update self.max_partition
        #
        curr_partition = seq_no / self.partition_size

        if ((curr_partition == 0) and
                (self.max_partition == self.highest_partition)):
            self.max_partition = 0
            self.min_partition = self.highest_partition

            print 'WRAPPED partitions %x %x' % (
                    self.min_partition, self.max_partition)

        elif curr_partition > self.max_partition:
            self.max_partition = curr_partition
            self.min_partition = curr_partition - 1
            if self.min_partition == 0:
                self.gen_wrap += 0x100000000

            print 'partitions %x %x' % (
                    self.min_partition, self.max_partition)

        # TODO: I think this still has a latent bug when the
        # first segment is in partition 1 or 0, because we
        # assume that the only way we see partitions 0 and 1 is
        # after wrapping.

        if (curr_partition == 0) and (self.max_partition == 0):
            increment = 0x100000000
        else:
            increment = 0

        # Obtain data to put in pkt to forward to DH
        #
        eff_seq_no = seq_no + increment + self.gen_wrap
        len_payload = len(pkt.get_payload())
        self.mole.extend(eff_seq_no + len_payload)
        new_payload = self.mole.copy(eff_seq_no, len_payload)

        # discard 2MB from the queue whenever the
        # queue grows to be more than 4MB.
        #
        # FIXME: this is a weak and incorrect heuristic;
        # it should depend on the current window size, not some
        # numbers I made up out of thin air

        too_full_size = 4 * 1024 * 1024
        trim_size = too_full_size / 2

        pending = self.mole.encoded_pending
        head_seq = pending.get_base() + pending.get_offset()

        if pending.get_len() > too_full_size:
            print 'DISCARDING FROM MOLE QUEUE seq_no %.8x' % eff_seq_no
            self.mole.reset_base(head_seq + trim_size)

        # Forward on modified pkt to DH
        #
        pkt.set_same_size_payload(new_payload, 0, len(new_payload))
        pkt.update_cksum()
        self.dr2dp.send_to_dr(str(pkt))

    def __str__(self):
        return """TLSUniFlowMonitor %d
client: %s port %d
state: %s
sentinel: %s
sentinel_label: %s
reassembler_forward.len: %d
reassembler_reverse.len: %d
""" % (id(self),
       socket.inet_ntoa(self.client_addr), self.client_port,
       self.state,
       binascii.b2a_hex(self.crypto.sentinel),
       self.crypto.sentinelLabel,
       self.reassembler_forward.len(),
       self.reassembler_reverse.len())




class BittorrentFlowMonitor(FlowMonitor):
    """
    Handle bidirectional Bittorrent flows
    """

    def __init__(self, tupl, cm, syn_options, isn, dr2dp):
        FlowMonitor.__init__(self, tupl, cm, syn_options, isn)

        self.recv_buf = ''
        self.dr2dp = dr2dp
        self.tunnel_type = const.BITTORENT_BI_TUNNEL
        self.sentinel_prefix = None
        self.sentinel_label = None
        self.DHexp = None

    def handshake(self, pkt):

        if (self.client_addr == None and
            pkt.get_dport() == const.BITTORRENT_SERVER_PORT):
            self.client_addr = pkt.get_src()
            self.client_port = pkt.get_sport()

        # Deal with acks
        #
        if pkt.get_payload_len() == 0:
            self.dr2dp.send_to_dr(str(pkt))
            return

        # If we see a RST or FIN, abandon the hijack
        # and send the packet to the DH.
        #
        flags = pkt.get_flags()
        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self.dr2dp.send_to_dr(str(pkt))
            self.cm.remove_flow(self.flow_tuple)
            return

        if pkt.get_sport() == const.BITTORRENT_SERVER_PORT:
            self.serverToClient(pkt)
        else:
            self.clientToServer(pkt)

    def serverToClient(self, pkt):

        self.reassembler_reverse.add_pkt(pkt)

        if self.state != 'Hijacked':
            self.dr2dp.send_to_dr(str(pkt))

        while self.state != 'Hijacked':
            msg = self.serverMsgRecv()

            if msg == None:
                return
            else:
                self.serverMsgProcess(msg)

    def clientToServer(self, pkt):

        self.reassembler_forward.add_pkt(pkt)

        if self.state != 'Hijacked':
            self.dr2dp.send_to_dr(str(pkt))

        while self.state != 'Hijacked':
            msg = self.clientMsgRecv()

            if msg == None:
                return
            else:
                self.clientMsgProcess(msg)

    def serverMsgRecv(self):
        return None

    def clientMsgRecv(self):
        return None

    def serverMsgProcess(self, msg):
        return None

    def clientMsgProcess(self, msg):
        return None

    def checkSentinel(self, sentinel_prefix):

        self.sentinel_prefix = sentinel_prefix

        if sentinel_prefix in FlowMonitor.bittorrent_sentinels:
            self.sentinel_label = FlowMonitor.sentinels[sentinel_prefix]
            self.DHexp = FlowMonitor.bittorrent_sentinels[sentinel_prefix]
            return True

        elif sentinel_prefix in FlowMonitor.sentinels[sentinel_prefix]:
            self.sentinel_label = FlowMonitor.sentinels[sentinel_prefix]
            self.DHexp = None
            return True

        else:
            # False positive
            #
            self.sentinel_label = None
            self.DHexp = None
            print "Bittorrent sentinel is false positive"
            return False

class ConnectionMonitor(object):
    """-
    Manages Flows flows from DR2DP_DP

    Primary function (dp_recv):
    Accepts an incoming packet,
    determines what FlowMonitor it belongs to,
    creates a new FlowMonitor if one does not exist,
    and forwards the packet to the correct monitor
    """

    def __init__(self, send_to_dr_endpoint, remove_flow_cb, options,
                 permit_deadbeef_, http_uni_ct_dp, tls_uni_ct_dp):

        self.full_opts = options
        self.flowtable = {}
        self.send_to_dr_endpoint = send_to_dr_endpoint
        self.opts = options['tcp_engine']
        self.http_uni_ct_dp = http_uni_ct_dp
        self.tls_uni_ct_dp = tls_uni_ct_dp
        
        global permit_deadbeef
        permit_deadbeef = permit_deadbeef_

        # callback method for notifying DR to remove a flow
        # required parameters: src_addr, dst_addr, src_port, dst_port, protocol
        #
        self.remove_flow_cb = remove_flow_cb

        self.log = logging.getLogger('cb.tcphijack.con_mon')

        self.gc_flows() # Start the GC timer

        # Start the Hijack TUN device early so that CT can listen on it
        #
        TCPHijack.hijack_manager = HijackManager(self.opts)

    def redirect_flow(self, pkts, opts, dr2dp=None):
        """
        Got a new flow to redirect from the DR.
        """
        DEBUG and log_debug("Got redirect flow msg")

        pkt = Packet(pkts[0], read_only=False)
        tuple = pkt.get_tuple()
        self.dr2dp = dr2dp
        
        if tuple in self.flowtable:
            """
            We already know about this flow!

             1. If this is the original DR that reported the initial redirect,
                then there is an error somewhere in the system. Should we
                ignore this message? But what about the packets in the message?
                Maybe should just close/remove this flow due to invalid state.

             2. If this is not the original DR, but another multiple DR,
                attempting to redirect the flow, then the DR must be notified
                to remove (i.e., stop redirecting) the flow. Should we keep
                a list of DRs that have reported each flow?
            """
            print "Already know about flow %s" % str(tuple)
            return

        # What's the ISN of this flow?
        #
        isn = None
        for p in pkts:
            p = Packet(p, read_only=True)
            if isn is None or p.get_seq() < isn:
                isn = p.get_seq()

        if pkt.get_dport() == 443:
            self.flowtable[tuple] = TLSUnknownFlowMonitor(
                    tuple, self, opts, isn, dr2dp)

        elif pkt.get_dport() == 80:
            self.flowtable[tuple] = HTTPUnknownFlowMonitor(
                    tuple, self, opts, isn, dr2dp)

        elif pkt.get_dport() == const.BITTORRENT_SERVER_PORT:
            self.flowtable[tuple] = BittorrentFlowMonitor(
                    tuple, self, opts, isn, dr2dp)
        else:
            print "ConnMon Redirect Flow: unknown port"
            return
        
        # DR already forwarded on pkts[:-1], so load those up
        #
        try:
            flow_entry = self.flowtable[tuple]            
        except:
            print "flow_entry does not exist"
            return
        
        for pkt in pkts[:-1]:
            pkt = Packet(pkt, read_only=True)

            if pkt.get_sport() == 443:
                flow_entry.reassembler_reverse.add_pkt(pkt)

            elif pkt.get_dport() == 443:
                flow_entry.reassembler_forward.add_pkt(pkt)

                if flow_entry.tunnel_type == const.CREATE_TLS_BI_TUNNEL:
                    self.flowtable[tuple] = TLSFlowMonitor(
                            flow_entry, self.dr2dp)
                elif flow_entry.tunnel_type == const.CREATE_TLS_UNI_TUNNEL:
                    self.flowtable[tuple] = TLSUniFlowMonitor(
                            flow_entry, self.dr2dp, self.tls_uni_ct_dp)

            elif pkt.get_sport() == 80:
                DEBUG and log_debug("reverse pkt")

            elif pkt.get_dport() == 80:
                flow_entry.traffic_from_client(pkt)
                if flow_entry.tunnel_type == const.CREATE_HTTP_BI_TUNNEL:
                    self.flowtable[tuple] = HTTPBiFlowMonitor(
                            flow_entry, self.dr2dp)
                elif flow_entry.tunnel_type == const.CREATE_HTTP_UNI_TUNNEL:
                    self.flowtable[tuple] = HTTPUniFlowMonitor(
                            flow_entry, self.dr2dp, self.http_uni_ct_dp)

            elif pkt.get_sport() == const.BITTORRENT_SERVER_PORT:
                flow_entry.reassembler_reverse.add_pkt(pkt)

            elif pkt.get_dport() == const.BITTORRENT_SERVER_PORT:
                flow_entry.reassembler_forward.add_pkt(pkt)
            else:
                print "Initial pkt: unexpected pkt port"

        # Start state processing/forwarding) on final packet
        #
        pkt = Packet(pkts[-1])
        if (pkt.get_sport() == 80 or pkt.get_sport() == 443 or
            pkt.get_sport() == const.BITTORRENT_SERVER_PORT):
            flow_entry.traffic_to_client(pkt)

        elif pkt.get_dport() == 80 or pkt.get_dport() == 443:
            # Add pkt to reassembler and process packet
            #
            flow_entry.traffic_from_client(pkt)

            if flow_entry.tunnel_type == const.CREATE_HTTP_BI_TUNNEL:
                self.flowtable[tuple] = HTTPBiFlowMonitor(
                        flow_entry, self.dr2dp)

            elif flow_entry.tunnel_type == const.CREATE_HTTP_UNI_TUNNEL:
                self.flowtable[tuple] = HTTPUniFlowMonitor(
                        flow_entry, self.dr2dp, self.http_uni_ct_dp)

            elif flow_entry.tunnel_type == const.CREATE_TLS_BI_TUNNEL:
                self.flowtable[tuple] = TLSFlowMonitor(
                        flow_entry, self.dr2dp)

            elif flow_entry.tunnel_type == const.CREATE_TLS_UNI_TUNNEL:
                self.flowtable[tuple] = TLSUniFlowMonitor(
                        flow_entry, self.dr2dp, self.tls_uni_ct_dp)

        elif pkt.get_dport() == const.BITTORRENT_SERVER_PORT:
            flow_entry.traffic_from_client(pkt)
        else:
            print "Subsequent packet: unexpected pkt port"

    def dp_recv(self, pkt):
        """
        DP gets a packet from the DR and sends it to the
        appropriate flow monitor for processing
        """
        pkt = Packet(pkt,read_only=False)
        tuple = pkt.get_tuple('c2d')
        tuple_rev = pkt.get_tuple('d2c')
        DEBUG and log_debug("CM: pkt from DR: %s" % strNetTuple(tuple))

        try:
            if tuple in self.flowtable:

                flow_entry = self.flowtable[tuple]
                flow_entry.traffic_from_client(pkt)

                if flow_entry.tunnel_type == const.CREATE_HTTP_BI_TUNNEL:
                    self.flowtable[tuple] = HTTPBiFlowMonitor(
                            flow_entry, self.dr2dp)

                elif flow_entry.tunnel_type == const.CREATE_HTTP_UNI_TUNNEL:
                    self.flowtable[tuple] = HTTPUniFlowMonitor(
                            flow_entry, self.dr2dp, self.http_uni_ct_dp)

                elif flow_entry.tunnel_type == const.CREATE_TLS_BI_TUNNEL:
                    self.flowtable[tuple] = TLSFlowMonitor(
                            flow_entry, self.dr2dp)

                elif flow_entry.tunnel_type == const.CREATE_TLS_UNI_TUNNEL:
                    self.flowtable[tuple] = TLSUniFlowMonitor(
                            flow_entry, self.dr2dp, self.tls_uni_ct_dp)

            elif tuple_rev in self.flowtable:
                self.flowtable[tuple_rev].traffic_to_client(pkt)

            else:
                # DP is not actively redirecting this flow;
                # notify DR to remove (i.e., stop redirecting) the flow
                #
                self.remove_flow(tuple)
                DEBUG and log_debug("CM: dropping packet %s" % pkt.pretty())
                return

        except TypeError as e:
            log_error("CM: typeerror, bad flow, removing from flowtables; %s" % str(e))
            self.remove_flow(tuple)
            return

        except KeyError as e:
            log_error("CM: keyerror, bad flow, removing from flowtables; %s" % str(e))
            self.remove_flow(tuple)
            return

    def handle_icmp(self, tuple, pkt, reverse = False):
        """
        Handle ICMP packet.
        """

        DEBUG and log_debug("CM: ICMP from DR: %s" % strNetTuple(tuple))

        icmp_pkt = Packet(pkt, read_only=False)
        if icmp_pkt.is_icmp() != True:
            DEBUG and log_debug("CM: invalid ICMP packet")
            return

        tuple_rev = (tuple[2], tuple[3], tuple[0], tuple[1])

        try:
            if reverse == False and tuple in self.flowtable:
                self.flowtable[tuple].handle_icmp(icmp_pkt)

            elif reverse == True and tuple_rev in self.flowtable:
                self.flowtable[tuple_rev].handle_icmp(icmp_pkt, reverse)

            else:
                # DP is not actively redirecting this flow
                self.send_to_dr_endpoint(str(pkt))
                DEBUG and log_debug("CM: dropping ICMP packet")
                return

        except Exception as e:
            log_error("CM: exception handling ICMP: %s" % str(e))
            return

    def remove_flow_deferred(obj, tuple):
        """
        Remove a flow, but after a short delay
        """

        def rmflow_callback(obj, tuple):
            print 'DEFERRED RMFLOW (%s)' % strNetTuple(tuple)
            obj.remove_flow(tuple)

        reactor.callLater(0.3, rmflow_callback, obj, tuple)

    def remove_flow(self, tuple):
        """
        Remove flow from table, and notify DR to no longer redirect.

        When called from within a FlowMonitor class this should be the
        very last action performed before returning from the class.
        """
        DEBUG and log_debug("CM: remove flow %s" % strNetTuple(tuple))

        # The protocol field is hardcoded to be TCP (i.e., 6) due to the
        # fact that the flow tuple does not include the protocol. This isn't
        # a problem for now since Curveball only handles TCP traffic flows.
        # However, in the future we may want the flow tuple to include the
        # protocol field.
        #
        self.remove_flow_cb(tuple[0], tuple[2], tuple[1], tuple[3], 6)

        try:
            # Drop the hijack state, if there is any
            #
            if self.flowtable[tuple].hijack:
                self.flowtable[tuple].hijack.drop()
            self.flowtable.pop(tuple)

        except KeyError:
            log_warn('remove_flow: tuple does not exist')

#        for monitor in self.flowtable.itervalues():
#            print 'TUPLE STILL IN FLOWTABLE: %s' % (str
#                  (str(socket.inet_ntoa(monitor.flow_tuple[0])) + ", " +
#                   str(monitor.flow_tuple[1]) + " -> " +
#                   str(socket.inet_ntoa(monitor.flow_tuple[2])) + ", " +
#                   str(monitor.flow_tuple[3])))

    def gc_flows(self):
        """
        Find any stale flows and remove them from the table
        """
        to_remove = []
        cur_time = time.time()
        expire_time = int(self.opts['track_flow_timeout'])

        for monitor in self.flowtable.itervalues():
            if cur_time - monitor.last_seen > expire_time:
                to_remove.append(monitor.flow_tuple)

        for tuple in to_remove:
            self.remove_flow(tuple)

        # Restart the GC clock..
        #
        reactor.callLater(int(self.opts['tracker_gc_timeout']), self.gc_flows)

    def cm_callback(self, src_addr):
        """
        The CT is asking for the sentinel for the new hijack
        flow it has just received.  It tells us the src address
        and port it saw, and we have to figure out what
        flow that belongs to and return the sentinel
        """
        hijack_tuple = (socket.inet_aton(src_addr[0]), src_addr[1])

        # TODO This is a linear search! Could speed up but gets messy
        #
        for monitor in self.flowtable.itervalues():
            if monitor.hijack and monitor.hijack.hijack_tuple[:2] == hijack_tuple:
                return monitor

        log_warn("cm_callback: Could not find sentinel!")
        return (None, None)

    def cm_http_callback(self, src_addr):
        """
        The CT is asking for the sentinel for the new hijack
        flow it has just received.  It tells us the src address
        and port it saw, and we have to figure out what
        flow that belongs to and return the sentinel
        """
        hijack_tuple = (socket.inet_aton(src_addr[0]), src_addr[1])

        # TODO This is a linear search! Could speed up but gets messy
        #
        for monitor in self.flowtable.itervalues():
            if monitor.hijack and monitor.hijack.hijack_tuple[:2] == hijack_tuple:

                tunnel_params = (
                        monitor.nonce_client +
                        monitor.nonce_dp +
                        monitor.premaster +
                        monitor.decoupled_ID +
                        monitor.seqNum_C2D_Rand +
                        monitor.content_type + const.END_LINE +
                        monitor.server_name )

                if monitor.sentinel.startswith( const.SENTINEL_DEADBEEF ):
                    return const.FULL_SENTINEL_DEADBEEF + tunnel_params

                try:
                    return (monitor.sentinel +
                            FlowMonitor.sentinels[monitor.sentinel] +
                            tunnel_params)

                except KeyError:
                    log_warn('sentinel does not exist')
                    return None

        log_warn("cm_http_callback: Could not find sentinel!")
        return None

    def cm_bittorrent_callback(self, src_addr):
        """
        The CT is asking for the sentinel for the new hijack
        flow it has just received.  It tells us the src address
        and port it saw, and we have to figure out what
        flow that belongs to and return the sentinel
        """
        hijack_tuple = (socket.inet_aton(src_addr[0]), src_addr[1])

        for monitor in self.flowtable.itervalues():

            if (monitor.hijack and
                monitor.hijack.hijack_tuple[:2] == hijack_tuple):

                try:
                    client_data = (monitor.sentinel_prefix +
                                   monitor.sentinel_label +
                                   monitor.DHexp)

                    return client_data

                except KeyError:
                    print 'bittorrent sentinel does not exist'
                    return None

        print "cm_bittorent_callback: Could not find sentinel!"
        return None

    def cm_close_callback(self, src_addr):
        """
        CT_DP or HTTP_CT_DP is telling us this flow is dead
        """
        hijack_tuple = (socket.inet_aton(src_addr[0]), src_addr[1])

        for monitor in self.flowtable.itervalues():

            if monitor.hijack and monitor.hijack.hijack_tuple[:2] == hijack_tuple:
                self.remove_flow_deferred(monitor.flow_tuple)
                # Need to break out of loop, because otherwise will be looping
                # over a dictionary in which the entries have changed
                #
                break

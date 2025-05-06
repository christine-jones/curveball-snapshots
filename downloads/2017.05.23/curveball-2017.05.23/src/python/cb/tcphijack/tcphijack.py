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

import socket
import os
import struct
import logging
import dpkt
import binascii
import time
import sys

from twisted.internet import reactor

import cb.util.flow
from cb.util import free_src
import cb.util.free_src
from cb.noc.sentinel_watcher import SentinelManager
import cb.util.dpkt_util as dpkt_util
from cb.util.packet import Packet
from cb.util.twistedtun import TwistedTUN

import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))
# FIXME -- replace DEBUG and log_debug(...) with self.log.debug(...)
def log_debug(msg):
    print >> sys.stderr, 'tcphijack: %s' % msg

# FIXME -- replace log_warning with self.log.warning
def log_warning(msg):
    print >> sys.stderr, 'tcphijack(warning): %s' % msg

# FIXME -- replace log_info with self.log.info
def log_info(msg):
    print >> sys.stderr, 'tcphijack(info): %s' % msg


class HijackManager(object):
    """
    Creates a TUN device and listens for packets
    to come back from the decoy on it.  Then determines
    which hijack object owns that flow and forwards it there
    """
    def __init__(self, opts):
        self.tuples = {}
        self.opts = opts
        self.log = logging.getLogger('cb.tcphijack.hijackmgr')
        self.tun = TwistedTUN(lambda x: self.traffic_to_client(Packet(x, read_only=False)), '',
                           self.opts['tun_ip'], self.opts['tun_netmask'])

        # &&& TODO: fix this.  It shouldn't be necessary to futz with the MTU
        # and I suspect that having small packets lets us be detected.
        # set_mtu = 'ifconfig %s mtu 1400' % self.tun.iface_name()
        # os.system(set_mtu)

    def traffic_to_client(self, pkt):
        """
        Flows that come in from the TUN device toward the client
        need to get shipped off to the appropriate hijack
        """
        DEBUG and log_debug("HijackManager: Received pkt from TUN: %s"
                            % pkt.pretty())

        tuple = pkt.get_tuple('d2c')
        if tuple in self.tuples:
            self.tuples[tuple].traffic_to_client(pkt)

    def register_tuple(self, hijack, tuple):
        # Reverse it because that's how packets will come from dest
        self.tuples[tuple] = hijack

    def unregister_tuple(self, tuple):
        self.tuples.pop(tuple)




class TCPHijack(object):
    free_srcs = None
    hijack_manager = None

    def __init__(self, pkt, flow_tuple, opts, send_to_dr, syn_options, isn=None):
        self.flow_tuple = flow_tuple
        self.syn_options = syn_options
        self.buffer = []
        self.opts = opts
        self.send_to_dr = send_to_dr

        self.seq_offset = None
        self.decoy_time = None
        self.ts_offset = None
        self.log = logging.getLogger('cb.tcphijack.hijack')
        self.state = 'Hijacking'

        # Keep track of the last seen sequence from client
        self.next_seq = None
        self.last_ack = None

        if TCPHijack.free_srcs is None:
            TCPHijack.free_srcs = free_src.FreeSrc(opts['tun_src_net'],
                                          int(opts['tun_max_conn']))

        if TCPHijack.hijack_manager is None:
            TCPHijack.hijack_manager = HijackManager(opts)

        (src, port) = TCPHijack.free_srcs.alloc_src()

        self.hijack_tuple = (socket.inet_aton(src), port,
              socket.inet_aton(opts['tun_ip']),
              flow_tuple[3])

        TCPHijack.hijack_manager.register_tuple(self, self.hijack_tuple)

        self.init_hijack(pkt, isn)

    def __del__(self):
        self.drop()

    def drop(self):

        # If we don't have a hijack_tuple, then we can't release it.
        # This shouldn't happen, so we note this.
        #
        if not self.hijack_tuple:
            print 'WARNING: TCPHijack.drop() called on non-hijacked conn'
            return

        TCPHijack.hijack_manager.unregister_tuple(self.hijack_tuple)

        # Send a RST to the listener of the hijack
        # in case it hasn't dropped this flow yet
        if not self.next_seq is None:
            (fsrc, fsport, fdst, fdport) = self.flow_tuple
            rst = dpkt.ip.IP(src=fsrc, dst=fdst, p=dpkt.ip.IP_PROTO_TCP,
                     data=dpkt.tcp.TCP(sport=fsport, dport=fdport,
                                       flags=dpkt.tcp.TH_RST,
                                       seq=self.next_seq,
                                       ack=self.last_ack))
            rst.len += len(rst.data)

            self.traffic_from_client(Packet(str(rst), read_only=False), buffer=False)

        # TODO: This might be endian-specific.  Investigate.
        #
        dotted_quad = '.'.join([ '%d' % ord(x) for x in self.hijack_tuple[0] ])
        TCPHijack.free_srcs.free_src((dotted_quad, self.hijack_tuple[1]))

    def init_hijack(self, pkt, isn=None):
        """
        init_hijack: Initialize a hijack

        This function allocates an internal addr/port to use for
        communication with the kernel.  It then sends a syn packet
        to initiate a TCP connection with the kernel.
        """

        # FIXME: no longer have to guess in the symmetric case
        # GUESS THE TCP/IP OPTIONS
        opts = []

        # assume we're using SACK
        opts.append('\x04\x02') # SACKOK

        # assume the MSS is 1460
        opts.append(struct.pack('>BBH', dpkt.tcp.TCP_OPT_MSS, 4, 1460))

        nop = struct.pack('>B', dpkt.tcp.TCP_OPT_NOP)

        (tsv,tsecr,index) = pkt.parse_timestamp()


        if not index is None:
            timestamp = pkt.buff[index:index+10]
            if tsv:
                opts.append(timestamp)
                self.decoy_time = tsecr


        # for earlier kernels, we ignored window scale.  Don't ignore now.
        # guess the window scale size by looking at the initial window size
        scale = 1
        while pow(2, scale) * pkt.get_window() < 10000:
            scale += 1
        opts.append(struct.pack('>BBB', dpkt.tcp.TCP_OPT_WSCALE, 3, scale))

        while len(''.join(opts)) % 4 != 0:
            opts.append(nop)


        if isn is None:
            isn = pkt.get_seq()-1

        # CREATE THE SYN PACKET
        syn = dpkt.ip.IP(src=self.flow_tuple[0],
                         dst=self.flow_tuple[2],
                         p=dpkt.ip.IP_PROTO_TCP,
                         data=dpkt.tcp.TCP(sport=self.flow_tuple[1],
                                           dport=self.flow_tuple[3],
                                           seq=isn,
                                           flags=dpkt.tcp.TH_SYN,
                                           opts=''.join(opts)))


        syn.data.off = (20 + len(syn.data.opts)) >> 2
        syn.len += len(syn.data)

        self.buffer = [pkt]

        if self.log.getEffectiveLevel() <= logging.DEBUG:
            DEBUG and log_debug("Sending to c2d_nat -> %s" 
                                % cb.util.dpkt_util.dpkt_to_str(syn))

        self.traffic_from_client(Packet(str(syn), read_only=False), buffer=False)
        #os.write(self.state.engine_fd, str(syn))


    def init_hijack_response(self, pkt):
        # Is it a SYN/ACK?  If so send the ack and any queued
        # packets from the client

        DEBUG and log_debug("init_hijack_response: %s" % pkt.pretty())

        if (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK) == pkt.get_flags():
            # What's the sequence offset between the decoy dest
            # and the tcp engine?
            if not self.buffer:
                log_error("There should be a data packet buffered (the one causing the hijack): %s" % pkt.pretty())
                return

            # Send the ACK
            self.ack_synack(pkt)

            # Set seq_offset after synack so that c2d_nat
            # doesn't overwrite ack_synack's sequence
            seq_offset = pkt.get_seq() + 1 - self.buffer[0].get_ack()
            self.seq_offset = seq_offset

            # TCP Timestamp Offset
            if not self.decoy_time is None:
                (tsv,tsr,index) = pkt.parse_timestamp()
                if not tsv is None:
                    dp_time = tsv
                    self.ts_offset = dp_time - self.decoy_time

            """
            Only reset if bidirectional
            """
            # RST connection to original destination
            self.send_rst(pkt.get_ack())

            # We've officially hijacked the connection
            self.state = 'Hijacked'


            # Forward queued packets on to the tcp engine (with NAT)
            for qpkt in self.buffer:
                self.traffic_from_client(qpkt)

            self.buffer = []


    def send_rst(self, seq):
        """
        Sends a RST to the decoy destination

        Arguments:
            hijack: The hijack this relates to
            seq: The sequence that the decoy dest is expecting next

        """

        (fsrc, fsport, fdst, fdport) = self.flow_tuple

        DEBUG and log_debug("tcphijack.send_rst: %s" % str(self.flow_tuple))

        rst = dpkt.ip.IP(src=fsrc, dst=fdst, p=dpkt.ip.IP_PROTO_TCP,
                 data=dpkt.tcp.TCP(sport=fsport, dport=fdport,
                                   flags=dpkt.tcp.TH_RST,
                                   seq=seq))
        rst.len += len(rst.data)

        self.send_to_dr(rst, False) # false indicates packet to decoy


    def ack_synack(self, pkt):
        """
        ack_synack: Respond to a synack with an ack
        """

        (src, sport, dst, dport) = self.flow_tuple

        DEBUG and log_debug("tcphijack.ack_synack: %s" % str(self.flow_tuple))

        ack = dpkt.ip.IP(src=src,
                         dst=dst,
                         p=dpkt.ip.IP_PROTO_TCP,
                         data=dpkt.tcp.TCP(
                                sport=sport,
                                dport=dport,
                                flags=dpkt.tcp.TH_ACK,
                                seq=pkt.get_ack(),
                                ack=pkt.get_seq()+1))

        (tsv,tsr,index) = pkt.parse_timestamp()

        if not tsv is None:
            timestamp = pkt.buff[index:index+10]
            opts = []
            (typ, length, tsval, tsecr) = struct.unpack('>BBII', timestamp)
            # Just reuse our original tsval, but do echo the engine's
            reply = struct.pack('>BBII', typ, length, tsecr, tsval)
            opts.append(reply)
            nop = struct.pack('>B', dpkt.tcp.TCP_OPT_NOP)
            opts.append(nop)
            opts.append(nop)
            ack.data.opts = ''.join(opts)
            ack.data.off = (20 + len(ack.data.opts)) >> 2


        ack.len += len(ack.data)
        self.traffic_from_client(Packet(str(ack), read_only=False), buffer=False)


    def traffic_from_client(self, pkt, buffer=True):

        DEBUG and log_debug("tcphijack.traffic_from_client: %s, %s"
                            % (self.state, pkt.pretty()))

        if not buffer or self.state == 'Hijacked':
            # We need to keep track of the last seen seq
            # in case we need to reset the flow at any given moment
            self.next_seq = pkt.get_seq() + pkt.get_payload_len()
            self.last_ack = pkt.get_ack()

            self.c2d_nat(pkt)
            TCPHijack.hijack_manager.tun.write(str(pkt))

        elif self.state == 'Hijacking':
            self.buffer.append(pkt)


    def traffic_to_client(self, pkt):
        """
        Forward: Send the packet on back to the DR

        """

        DEBUG and log_debug("tcphijack.traffic_to_client: %s, %s"
                            % (self.state, pkt.pretty()))

        self.d2c_nat(pkt)

        if self.state == 'Hijacking':
            # This should be the syn/ack we're waiting for
            self.init_hijack_response(pkt)

        elif self.state == 'Hijacked':
            self.send_to_dr(pkt)

        else:
            log_error("Unknown flow state: %s" % self.state)




    def c2d_nat(self, pkt):
        """
        Forward a packet on to the TCP Engine

        Forward converts the packet to internal usage
        src/dst addresses and ports so that the TCP
        engine knows how to handle it.  It also
        modifies the ack value to match what the TCP
        engine is expecting.

        Parameters:
            pkt: the packet to forward

        """

        (src, sport, dst, dport) = self.hijack_tuple

        out = pkt
        out.set_src(src)
        out.set_dst(dst)
        out.set_sport(sport)
        out.set_dport(dport)

        DEBUG and log_debug("tcphijack.c2d_nat: %s" % out.pretty())

        if not self.seq_offset is None:
            out.set_ack((out.get_ack() + self.seq_offset) & 0xffffffff)

        if not self.ts_offset is None:
            out.offset_timestamp(self.ts_offset, False)

        out.update_cksum()


    def d2c_nat(self, pkt):
        """
        Forward a packet on to the connection manager

        Forward takes a packet from the TCP Engine (kernel) and
        converts it back to the original ingress_flow addresses
        and ports.  It also changes the sequence number to that
        expected by the source.

        Arguments:
            pkt: The packet to forward

        """

        (src, sport, dst, dport) = self.flow_tuple

        pkt.set_src(dst)
        pkt.set_dst(src)
        pkt.set_sport(dport)
        pkt.set_dport(sport)

        DEBUG and log_debug("tcphijack.d2c_nat: %s" % pkt.pretty())

        if self.seq_offset is None:
            if not self.state == 'Hijacking':
                log_warning("There should not be a packet to forward without a seq_offset: %s" % pkt.pretty())
                return

        else:
            pkt.set_seq( (pkt.get_seq() - self.seq_offset) & 0xffffffff)

        if not self.ts_offset is None:
            pkt.offset_timestamp(-1 * self.ts_offset, True)

        if self.log.getEffectiveLevel() <= logging.DEBUG:
            DEBUG and log_debug( "Received from TCP Engine: %s" % pkt.pretty())

        pkt.update_cksum()


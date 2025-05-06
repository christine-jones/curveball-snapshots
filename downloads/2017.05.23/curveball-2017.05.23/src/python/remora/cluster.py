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
Implements the older "cluster" heuristic for choosing
decoys to add to a cluster activity.

Does not match the current interface for a RemoraDetector;
SHOULD NOT BE USED until brought up-to-date.
"""

import socket
import struct
import sys

from twisted.internet import reactor

from remora.packet_sniffer import PacketSniffer

class RemoraDetectorCluster(object):

    PCAP_FILTER = '((tcp[tcpflags] & tcp-syn) != 0) and \
                    (dst port 80 || dst port 443)'

    # flow cluster detection states
    RD_CLUSTER_WAIT      = 0
    RD_CLUSTER_POTENTIAL = 1
    RD_CLUSTER_ACTIVE    = 2

    def __init__(self, server, interface, mac_addr):
        self.server = server
        self.interface = interface
        self.mac_addr = mac_addr

        self.pcap_filter = self.PCAP_FILTER
        self.pcap_filter += ' and ether src ' + self.mac_addr

        # ENABLE CONFIGURATION OF NEXT THREE PARAMETERS

        # minimum idle time (in sec) before start of flow cluster
        self.idle_threshold = 2

        # maximum time (in sec) between flows within a cluster
        self.max_flow_gap = 2

        # number of flows needed to make a cluster
        self.min_flows_required = 5

        assert self.idle_threshold >= self.max_flow_gap

        # keeps track of current flow cluster detection state
        self.flow_cluster_state = self.RD_CLUSTER_WAIT

        # history of observed flow clusters
        self.flow_clusters = dict()

        # current flow cluster info
        self.current_flowkey = None
        self.current_flowlist = None

        # remember state between pkt recptions
        self.prev_pkt_ts = 0
        self.num_flows = 0

        # start sniffing packets
        reactor.callInThread(self.start_packet_sniffer)

    def start_packet_sniffer(self):
        try:
            p = PacketSniffer(self.interface, self.incoming_pkt)
        except:
            return

        p.set_filter(self.pcap_filter)
        p.recv()

    def incoming_pkt(self, ts, pkt):
        reactor.callFromThread(self.pkt_handler, ts, pkt)

    def pkt_handler(self, ts, pkt):

        # convert time tuple ([sec,microsec]) to single float value
        (sec, microsec) = ts
        pkt_ts = sec + (microsec / 1e6)

        # parse the packet and extract a unique flow key
        flowkey = self.extract_flowkey(pkt)
        if flowkey == None:
            return

        # initialize state on first packet reception
        if self.prev_pkt_ts == 0:
            self.prev_pkt_ts = pkt_ts
            return

        # determine time since previous packet recption
        elapsed_time = pkt_ts - self.prev_pkt_ts
        self.prev_pkt_ts = pkt_ts

        # idle period, possible start of a new flow cluster
        if elapsed_time > self.idle_threshold:
            self.flow_cluster_state = self.RD_CLUSTER_POTENTIAL
            self.num_flows = 0

            self.current_flowkey = flowkey
            self.current_flowlist = []

            # we've seen this cluster before; report decoy
            if flowkey in self.flow_clusters:
                flowlist = self.flow_clusters[flowkey]
                decoy_flowkey = flowlist[self.min_flows_required - 1]

                # determine decoy host to report
                (decoy_addr, decoy_port) = self.extract_decoy(decoy_flowkey)

                # notify server
                self.server.flow_cluster_detected(decoy_addr, decoy_port)

        # not a flow cluster, idle time too long between packets;
        # waiting for greater idle time to mark the start of new cluster
        elif elapsed_time > self.max_flow_gap:
            self.flow_cluster_state = self.RD_CLUSTER_WAIT
            self.num_flows = 0

            self.current_flowkey = None
            self.current_flowlist = None

        # not an idle period
        else:
            if self.flow_cluster_state == self.RD_CLUSTER_POTENTIAL:
                # update the number of flows seen
                self.num_flows = self.num_flows + 1
                self.current_flowlist.append(flowkey)

                # flow cluster detected
                if self.num_flows == self.min_flows_required:
                    self.flow_cluster_state = self.RD_CLUSTER_ACTIVE

                    # update history
                    self.flow_clusters[self.current_flowkey] = []
                    self.flow_clusters[self.current_flowkey].extend(
                        self.current_flowlist)

    def extract_flowkey(self, pkt):

        eth_len = 14
        if len(pkt) < eth_len:
            print >> sys.stderr, ("packet does not include ethernet header")
            return None

        eth_header = struct.unpack('!6s6sH', pkt[0:eth_len])
        if eth_header[2] != 0x800:
            print >> sys.stderr, ("invalid ethernet protocol")
            return None

        ip_len = 20
        if len(pkt) < (eth_len + ip_len):
            print >> sys.stderr, ("packet does not include ip header")
            return None

        ip_header = struct.unpack('!BBHHHBBH4s4s',
                pkt[eth_len:(eth_len + ip_len)])

        ihl = ip_header[0] & 0xF
        ip_len = ihl * 4

        protocol = ip_header[6]
        if protocol != 6:
            print >> sys.stderr, ("packet is not tcp")
            return None

        tcp_len = 20
        if len(pkt) < (eth_len + ip_len + tcp_len):
            print >> sys.stderr, ("packet does not include tcp header")
            return None

        tcp_header = struct.unpack('!HHLLBBHHH',
                pkt[(eth_len + ip_len):(eth_len + ip_len + tcp_len)])

        daddr = socket.inet_ntoa(ip_header[9])
        dport = tcp_header[1]

        flowkey = '%s-%s' % (daddr, dport)
        return flowkey

    def extract_decoy(self, flowkey):
        (daddr, dport) = flowkey.split('-')

        return (daddr, int(dport))


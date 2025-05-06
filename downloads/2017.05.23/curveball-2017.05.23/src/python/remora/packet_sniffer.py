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

import pcapy
import sys

# simple class for live packet capture

class PacketSniffer(object):

    # pcap settings
    SNAP_LEN     = 1024
    PROMISCUOUS  = 0
    READ_TIMEOUT = 0

    def __init__(self, interface_name, pkt_cb, live_mode = True):

        # network interface from which to capture packets
        # if live_mode set to false, then interpreted as a filename
        self.interface_name = interface_name

        # callback to which to send captured packets
        self.pkt_cb = pkt_cb

        # capture packets from a network interface
        if live_mode:
            try:
                self.reader = pcapy.open_live(self.interface_name,
                        PacketSniffer.SNAP_LEN, PacketSniffer.PROMISCUOUS,
                        PacketSniffer.READ_TIMEOUT)

            except pcapy.PcapError, pce:
                print >> sys.stderr, ("PacketSniffer:__init__: " 
                        "error listening to interface %s, error: %s" % 
                        (self.interface_name, str(pce)))
                raise

        # read packets from a file
        else:
            try:
                self.reader = pcapy.open_offline(self.interface_name)

            except pcapy.PcapError, pce:
                print >> sys.stderr, ("PacketSniffer:__init__: "
                        "error opening file %s, error: %s" %
                        (self.interface_name, str(pce)))
                raise

    def set_filter(self, filter_string):
        """
        set packet capture filter prior to recv() call

        a filter is specified as a text string; the syntax and semantics of
        the string are as described by pcap-filter(7)
        """

        try:
            self.reader.setfilter(filter_string)
        except:
            print >> sys.stderr, ("PacketSniffer:set_filter: "
                    "error setting filter %s" % filter_string)

    def recv(self):
        # read packets until an interrupt or error occurs
        try:
            self.reader.loop(0, self.pkt_handler)

        except pcapy.PcapError, pce:
            print >> sys.stderr, ("PacketSniffer:recv: error in recv loop: " +
                    str(pce))
            raise

    def pkt_handler(self, hdr, data):
        # provide timestamp and packet buffer to callback
        self.pkt_cb(hdr.getts(), data)

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
Eavesdrops on DNS reponses sent to a local interface to
build a reverse-DNS map.

Only handles short (single-frame, single-packet) DNS-over-UDP responses.
Does not handle fragmented responses, and does not handle TCP at all.
"""

# requires package python-dnspython to be installed

import dns.message
import re
import struct
import sys

from twisted.internet import reactor

from remora.packet_sniffer import PacketSniffer

class RemoraDNSSniffer(object):
    """
    Used to sniff DNS traffic to construct maps from hostnames
    to IP addresses and vice versa.  These are used later to
    infer the hostnames that are used in web requests on connections
    whose destination IP addresses we observe.
    """

    # FIXME: should filter on the dst addr as well, to make sure
    # that the DNS queries we capture are addressed to this host.
    #
    # FIXME: should confirm that this response actually matches some
    # request and isn't just a spoofed packet that an adversary wants
    # us to think is a valid response.  An adversary could poison
    # our maps with whatever misleading info they desire.
    #
    PCAP_FILTER = 'udp and (src port 53)'

    def __init__(self, server, interface, mac_addr):
        self.server = server
        self.interface = interface
        self.mac_addr = mac_addr

        self.pcap_filter = self.PCAP_FILTER
        self.pcap_filter += ' and ether dst ' + self.mac_addr

        self.host2addr = dict()
        self.addr2host = dict()

        # start sniffing packets
        reactor.callInThread(self.start_packet_sniffer)

    def start_packet_sniffer(self):
        """
        Launch the pcap sniffer for DNS responses
        """

        try:
            sniffer = PacketSniffer(self.interface, self.incoming_pkt)
        except:
            return

        sniffer.set_filter(self.PCAP_FILTER)
        sniffer.recv()

    def incoming_pkt(self, timestamp, pkt):
        """
        Callback from the DNS packet sniffer; schedules a twisted
        callFromThread that actually does the real work.

        Because the synchronization model we use is based on twisted
        (which implicitly serializes almost everything) we can't
        safely modify any shared state here -- all we should do is
        schedule the pkt_handler callback to be called by twisted
        as soon as it is ready.
        """

        reactor.callFromThread(self.pkt_handler, timestamp, pkt)

    def pkt_handler(self, timestamp, pkt):
        """
        Extract info from a DNS response packet and update the maps

        TODO: this is half-baked.  It assumes that results always
        fit in a single packet, but an active adversary can use UDP
        fragmentation to ensure that this never happens.  In the
        long run, we must also implement reassembly.
        """

        eth_len = 14
        if len(pkt) < eth_len:
            print >> sys.stderr, ("packet does not include ethernet header")
            return None

        eth_header = struct.unpack('!6s6sH', pkt[0:eth_len])
        if eth_header[2] != 0x800:
            print >> sys.stderr, ("invalid ethernet protocol")
            return None

        # TODO: this probably fails if there are IP options

        ip_len = 20
        if len(pkt) < (eth_len + ip_len):
            print >> sys.stderr, ("packet does not include ip header")
            return None

        ip_header = struct.unpack('!BBHHHBBH4s4s',
                pkt[eth_len:(eth_len + ip_len)])

        ihl = ip_header[0] & 0xF
        ip_len = ihl * 4

        protocol = ip_header[6]
        if protocol != 17:
            print >> sys.stderr, ("packet is not UDP")
            return None

        # TODO: are the UDP options we need to consider as well?

        header_len = 8
        if len(pkt) < (eth_len + ip_len + header_len):
            print >> sys.stderr, ("packet does not include header")
            return None

        # Peeking into the UDP header is useful for diagnostics
        #
        # udp_header = struct.unpack('!HHHH',
        #         pkt[(eth_len + ip_len):(eth_len + ip_len + header_len)])
        #
        # sport = udp_header[0]
        # dport = udp_header[1]
        # dlen = udp_header[2]
        #
        # addr = ip_header[8]
        # src_addr = '%d.%d.%d.%d' % (
        #         ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]))
        # addr = ip_header[9]
        # dst_addr = '%d.%d.%d.%d' % (
        #         ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]))

        # FIXME: This is wrong, starting here.  We assume that we never
        # get a fragment.  We can't handle fragments
        #
        pkt_body = pkt[(eth_len + ip_len + 8):]

        try:
            dnsresp = dns.message.from_wire(pkt_body)
        except BaseException, exc:
            print 'DNS response did not parse: %s' % str(exc)
            return None

        # If the opcode isn't 0 (QUERY) or the response code isn't 0
        # (SUCCESS) then bail out
        #
        if (dnsresp.opcode() != 0) or (dnsresp.rcode() != 0):
            return None

        # print 'QUESTION: %s' % str(dnsresp.question)
        # print 'ANSWER: %s' % str(dnsresp.answer)
        # print dnsresp.__dict__
        # print dnsresp.rcode()
        # print dnsresp.opcode()

        # This is slightly insane, but it's easier to convert the records
        # to strings and then parse them again than it is to use the accessors
        # of the dnspython objects, which are wonderfully obfuscated (in the
        # spirit of DNS, I suppose)
        #

        requested_name = str(dnsresp.question[0]).split()[0]
        requested_name = re.sub('\.$', '', requested_name)
        # print 'REQUESTED NAME [%s]' % requested_name

        for ans in dnsresp.answer:
            # print 'DNS ANSWER %s' % str(ans)

            for row in str(ans).split('\n'):
                elems = row.split()

                # If it's not an "A" record, skip it.  We actually don't
                # want the canonical names; we only want the names that
                # the apps are using
                #
                if (elems[2] != 'IN') or (elems[3] != 'A'):
                    continue

                addr = elems[4]
                self.update_maps(requested_name, addr)

        # TODO: sometimes the answer comes back in a different format
        # and this ends up mapping a hostname to an alias, instead of an
        # IP address to the primary hostname.  This alternative format
        # MUST be recognized and processed correctly.

        # for diagnostics
        # print self.host2addr
        # print self.addr2host

    def update_maps(self, host, addr):
        """
        Update the maps between hostnames and IP addresses.

        Note that we don't just keep the map as element -> sets;
        we keep the sets in ordered lists by reference.  The lists
        are kept in order so that the newest references are at the
        head of the list.
        """

        # print 'UPDATING MAP %s %s' % (host, addr)

        # hostname -> addresses
        if host in self.host2addr:
            addrs = self.host2addr[host]
            if addr in addrs:
                addrs.remove(addr)
            addrs.insert(0, addr)
        else:
            self.host2addr[host] = [addr]

        # address -> hostnames
        if addr in self.addr2host:
            hosts = self.addr2host[addr]
            if host in hosts:
                hosts.remove(host)
            hosts.insert(0, host)
        else:
            self.addr2host[addr] = [host]


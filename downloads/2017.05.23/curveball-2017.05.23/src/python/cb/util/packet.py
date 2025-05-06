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

import struct
import dumbnet as dnet
import socket
import copy

flaglist = [(dnet.TH_SYN, 'S'), (dnet.TH_FIN, 'F'),
            (dnet.TH_RST, 'R'), (dnet.TH_PUSH, 'P'),
            (dnet.TH_ACK, 'A'), (dnet.TH_URG, 'U'),
            (dnet.TH_ECE, 'E'), (dnet.TH_CWR, 'C')]

def flags_to_str(flags):
    res = ''
    for (bit, val) in flaglist:
        if flags & bit:
            res += val
    return res

class Packet(object):
    """
    The Packet class is a light-weight and lazy packet parser
    and modifier.  In the default read_only mode, the packet
    string is not
    """
    def __init__(self, buff, read_only=False):
        self.read_only = read_only

        if read_only:
            self.buff = buff
            self.bytes = None
        else:
            self.bytes = bytearray(buff)
            # Raw points to the current bytes!
            self.buff = buffer(self.bytes)

        self.ihl = (ord(self.buff[0]) & 0x0f) << 2
        self.protocol = ord(self.buff[9])

        self.tcp = False
        self.icmp = False

        if self.protocol == 6:
            self.tcp = True
            self.thl = (ord(self.buff[self.ihl + 12]) & 0xf0) >> 2

        elif self.protocol == 1:
            self.icmp = True
            self.parse_icmp()

        self.need_cksum = False

    def is_icmp(self):
        return self.icmp == True

    def get_src(self):
        return self.buff[12:16]
    def set_src(self, src):
        self.need_cksum = True
        self.bytes[12:16] = src
    def get_dst(self):
        return self.buff[16:20]
    def set_dst(self, dst):
        self.need_cksum = True
        self.bytes[16:20] = dst
    def get_ttl(self):
        return self.buff[8]
    def set_ttl(self, ttl):
        self.need_cksum = True
        self.bytes[8] = ttl
    def get_identifier(self):
        return struct.unpack('!H', self.buff[4:6])[0]
    def set_identifier(self, identifier):
        self.need_cksum = True
        struct.pack_into('!H', self.bytes, 4, identifier)
    def get_sport(self):
        assert(self.tcp)
        return struct.unpack('!H', self.buff[self.ihl:self.ihl+2])[0]
    def set_sport(self, sport):
        assert(self.tcp)
        self.need_cksum = True
        struct.pack_into('!H', self.bytes, self.ihl, sport)
    def get_dport(self):
        assert(self.tcp)
        return struct.unpack('!H', self.buff[self.ihl+2:self.ihl+4])[0]
    def set_dport(self, dport):
        assert(self.tcp)
        self.need_cksum = True
        struct.pack_into('!H', self.bytes, self.ihl+2, dport)
    def get_seq(self):
        assert(self.tcp)
        return struct.unpack('!I', self.buff[self.ihl+4:self.ihl+8])[0]
    def set_seq(self, seq):
        assert(self.tcp)
        self.need_cksum = True
        struct.pack_into('!I', self.bytes, self.ihl+4, seq)
    def get_ack(self):
        assert(self.tcp)
        return struct.unpack('!I', self.buff[self.ihl+8:self.ihl+12])[0]
    def set_ack(self, ack):
        assert(self.tcp)
        self.need_cksum = True
        struct.pack_into('!I', self.bytes, self.ihl+8, ack)
    def get_window(self):
        assert(self.tcp)
        return struct.unpack('!H', self.buff[self.ihl+14:self.ihl+16])[0]
    def set_window(self, window):
        assert(self.tcp)
        self.need_cksum = True
        struct.pack_into("!H", self.bytes, self.ihl+14, window)
    def get_opts(self):
        assert(self.tcp)
        return self.buff[self.ihl+20:self.ihl+self.thl]
    def get_payload(self):
        if self.tcp:
            return self.buff[self.ihl+self.thl:]
        else:
            return self.buff[self.ihl:]

    def set_same_size_payload(self, p, i, p_len):

        z = str(p_len)
        s = '!' + z + 's'
        if self.tcp:
            struct.pack_into(s, self.bytes, self.ihl+self.thl+i, p)
        else:
            struct.pack_into(s, self.bytes, self.ihl+i, p)


    def get_payload_len(self):
        if self.tcp:
            return len(self.buff) - (self.ihl + self.thl)
        else:
            return len(self.buff) - self.ihl
    def get_tuple(self, d='c2d'):
        assert(self.tcp)
        t = (self.get_src(), self.get_sport(), self.get_dst(), self.get_dport())
        if d == 'c2d':
            return t
        else:
            return (t[2],t[3],t[0],t[1])
    def get_ip_cksum(self):
        return struct.unpack("!H", self.buff[10:12])[0]
    def get_tcp_cksum(self):
        assert(self.tcp)
        return struct.unpack("!H", self.buff[self.ihl+16:self.ihl+18])[0]
    def __len__(self):
        return len(self.buff)
    def get_flags(self):
        assert(self.tcp)
        return ord(self.buff[self.ihl+13])
    def set_flags(self, flags):
        assert(self.tcp)
        self.need_cksum = True
        self.bytes[self.ihl+13] = flags

    # ICMP PACKET

    ICMP_TYPE_DEST_UNREACH = 3
    ICMP_TYPE_REDIRECT = 5
    ICMP_TYPE_TIME_EXCEED = 11
    ICMP_TYPE_PARAM_PROB = 12

    def get_icmp_type(self):
        assert(self.icmp)
        return ord(self.buff[self.ihl])
    def get_icmp_code(self):
        return ord(self.buff[self.ihl + 1])

    def parse_icmp(self):
        assert(self.icmp)

        self.icmphl = 8
        self.embed_ip_offset = self.ihl + self.icmphl
        self.embed_ihl = (ord(self.buff[self.embed_ip_offset]) & 0x0f) << 2

        self.embed_tcp = False

        self.embed_protocol = ord(self.buff[self.embed_ip_offset + 9])
        if self.embed_protocol == 6:
            self.embed_tcp = True
            self.embed_tcp_offset = self.embed_ip_offset + self.embed_ihl
            self.embed_thl = \
                (ord(self.buff[self.embed_tcp_offset + 12]) & 0xf0) >> 2

        self.icmp_parsed = True

    def is_embed_tcp(self):
        assert(self.icmp)
        assert(self.icmp_parsed)
        return self.embed_tcp == True

    def set_icmp_src(self, src, sport):
        assert(self.icmp)
        assert(self.icmp_parsed)
        assert(self.embed_tcp)

        self.need_cksum = True

        addr_start = self.embed_ip_offset + 12
        addr_end   = self.embed_ip_offset + 16
        self.bytes[addr_start:addr_end] = src

        struct.pack_into('!H', self.bytes, self.embed_tcp_offset, sport)

    def set_icmp_dst(self, dst, dport):
        assert(self.icmp)
        assert(self.icmp_parsed)
        assert(self.embed_tcp)

        self.need_cksum = True

        addr_start = self.embed_ip_offset + 16
        addr_end   = self.embed_ip_offset + 20
        self.bytes[addr_start:addr_end] = dst

        struct.pack_into('!H', self.bytes, self.embed_tcp_offset + 2, dport)

    def __str__(self):
        if self.need_cksum:
            self.update_cksum()
            self.need_cksum = False

        if self.read_only:
            return str(self.buff)
        else:
            return str(self.bytes)

    def pretty(self):
        if self.tcp:
            return "%s:%d -> %s:%d [seq/ack: %d/%d] [%s] [%dB] "  % (socket.inet_ntoa(self.get_src()),
                                                    self.get_sport(),
                                                    socket.inet_ntoa(self.get_dst()),
                                                    self.get_dport(),
                                                    self.get_seq(),
                                                    self.get_ack(),
                                                    flags_to_str(self.get_flags()),
                                                    self.get_payload_len())
        else:
            return "%s -> %s [%dB]" % (socket.inet_ntoa(self.get_src()),
                                socket.inet_ntoa(self.get_dst()),
                                self.get_payload_len())

    def update_cksum(self):
        """ Updates the IP and transport checksums of the packet """
        new_raw = dnet.ip_checksum(self.buff)
        self.bytes = bytearray(new_raw)
        self.buff = buffer(self.bytes)
        self.need_cksum = False

    def parse_timestamp(self):
        """
        Search for a timestamp in the options buffer of a packet.

        If one is found, return (tsval, tsecr, index) where tsval and tsecr
        are the values from the timestamp, and index is the offset into the
        packet buffer where the timestamp is located.

        If none is found, return (None, None, None)
        """

        assert(self.tcp)
        index = self.ihl + 20
        buf = self.buff

        # Calculate where we can stop looking: since the timestamp option is 10
        # bytes long, if we have less than ten bytes remaining then we're not
        # going to find one.
        #
        end = (self.ihl + self.thl) - (10 - 1)
        # print '------'
        while index < end:
            # print 'index %d end %d ihl %d thl %d len %d' % (index, end,
            #         self.ihl, self.thl, len(buf))
            opt = ord(buf[index])
            if opt == dnet.TCP_OPT_TIMESTAMP:
                fields = buf[index + 2:index + 10]
                (tsval, tsecr) = struct.unpack('!II', fields)
                return (tsval, tsecr, index)
            elif opt == dnet.TCP_OPT_NOP:
                index += 1
            elif opt == dnet.TCP_OPT_EOL:
                return (None, None, None)
            else:
                opt_len = ord(buf[index + 1])
                if opt_len < 2:
                    return (None, None, None)
                else:
                    index += opt_len

        return (None, None, None)

    def offset_timestamp(self, offset, tsval):
        """
        Offsets the timestamp of the packet

        If tsval is true, then offset the tsval
        If tsval is false, then offset the tsecr

        Timestamp Option:
                  +-------+-------+---------------------+---------------------+
                  |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
                  +-------+-------+---------------------+---------------------+
                      1       1              4                     4
        """
        assert(self.tcp)
        self.need_cksum = True
        (tsv, tsr, ts_index) = self.parse_timestamp()
        if tsv is None:
            return
            #raise Exception("No timestamp to alter!")

        if tsval:
            struct.pack_into('>I', self.bytes, ts_index+2, tsv + offset)
        else:
            struct.pack_into('>I', self.bytes, ts_index+6, tsr + offset)


    def clone(self):

        new_buff = copy.copy( self.buff[:] )

        return Packet(new_buff, False)




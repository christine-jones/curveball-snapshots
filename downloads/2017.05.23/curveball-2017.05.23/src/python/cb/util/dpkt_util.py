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
import struct

import cb.util.platform

if cb.util.platform.PLATFORM == 'darwin':
    import dnet
else:
    import dumbnet as dnet

flaglist = [(dnet.TH_SYN, 'S'), (dnet.TH_FIN, 'F'),
            (dnet.TH_RST, 'R'), (dnet.TH_PUSH, 'P'),
            (dnet.TH_ACK, 'A'), (dnet.TH_URG, 'U'),
            (dnet.TH_ECE, 'E'), (dnet.TH_CWR, 'C')]

def find_timestamp_offset(buf):
    """
    Given buf containing a string of TCP options, find the offset of
    the beginning of the timestamp option, if there is one, or -1
    if there is not.
    """

    # The tcp timestamp option is 10 bytes long, so if we have fewer
    # than 10 bytes remaining, we can stop trying to find a timestamp.
    #
    # NOP and EOL options are one byte in length.  NOPs can be anywhere,
    # but EOL must be last, so when we see it we can stop -- although if
    # we do see it, it means that something is bogus because we should
    # never look at the last 9 bytes of the options.
    #
    # All the other options consist of the option field, a length field,
    # and then the contents (if any).  If the length is less than 2,
    # then the options are badly formed; return None.  Otherwise believe
    # that the len is correct, skip over the option, and continue.
    #
    # TODO: there are other constraints we could check: for example,
    # checking that the length field of each option is plausible for
    # that option -- most options have a fixed length and so len is
    # completely constrained.
    #

    off = 0
    while len(buf) >= 10:
        opt = ord(buf[0])

        if opt == dnet.TCP_OPT_TIMESTAMP:
            return off
        elif opt == dnet.TCP_OPT_NOP:
            buf = buf[1:]
            off += 1
        elif opt == dnet.TCP_OPT_EOL:
            return -1
        else:
            opt_len = ord(buf[1])
            if opt_len < 2:
                return -1
            else:
                buf = buf[opt_len:]

    return -1

def parse_timestamp(buf):
    """
    Given a TCP options buffer, look for a timestamp.

    If one is present, then return it.
    If no timestamp is present, or the options do not parse,
    then return None.
    """

    off = find_timestamp_offset(buf)
    if off < 0:
        return None
    else:
        return buf[off:off + 10]


def offset_timestamp(pkt, offset, tsval):
    """
    Given a packet, offset the tsval of the TCP options
    
    If tsval is true, then offset the tsval
    If tsval is false, then offset the tsecr
    
    Timestamp Option:
              +-------+-------+---------------------+---------------------+
              |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
              +-------+-------+---------------------+---------------------+
                  1       1              4                     4
    """
    buf = pkt.data.opts
    new = ''
    while buf:
        o = ord(buf[0])
        if o == dnet.TCP_OPT_TIMESTAMP:
            new += buf[:2]
            if tsval:
                tsval = struct.unpack('>I', buf[2:6])[0]
                new += struct.pack('>I', tsval + offset)
                new += buf[6:]
            else:
                new += buf[2:6]
                tsecr = struct.unpack('>I', buf[6:10])[0]
                new += struct.pack('>I', tsecr + offset)
                new += buf[10:]
                
            pkt.data.opts = new
            return
            
        elif o > dnet.TCP_OPT_NOP:
            new += buf[:ord(buf[1])]
            buf = buf[ord(buf[1]):]

        else:
            new += buf[0]
            buf = buf[1:]
            


def replace_timestamp(buf, timestamp):
    """ Given a tcp timestamp option and a TCP options buffer,
    replace the existing timestamp option in the buffer 
    with the given timestamp """
    
    opts = ''
    
    while buf:
        o = ord(buf[0])
        if o == dnet.TCP_OPT_TIMESTAMP:
            opts += timestamp
            opts += buf[ord(buf[1]):]
            return opts
        
        elif o > dnet.TCP_OPT_NOP:
            opts += buf[:ord(buf[1])]
            buf = buf[ord(buf[1]):]
            
        else:
            opts += buf[0]
            buf = buf[1:]

    
    return opts

def flags_to_str(flags):
    res = ''
    for (bit, val) in flaglist:
        if flags & bit:
            res += val
    return res

def dpkt_to_str(pkt):
    if pkt.p == dnet.IP_PROTO_TCP:
        return "%s:%d -> %s:%d [seq/ack: %d/%d] [%s] [%dB] "  % (socket.inet_ntoa(pkt.src), 
                                                pkt.data.sport,
                                                socket.inet_ntoa(pkt.dst), 
                                                pkt.data.dport,
                                                pkt.data.seq,
                                                pkt.data.ack,
                                                flags_to_str(pkt.data.flags), 
                                                len(pkt.data.data))
    elif pkt.p == dnet.IP_PROTO_UDP:
        return "%s:%d -> %s:%d"  % (socket.inet_ntoa(pkt.src), pkt.data.sport,
                                   socket.inet_ntoa(pkt.dst), pkt.data.dport)
    elif pkt.p == dnet.IP_PROTO_ICMP:
        return "%s -> %s ICMP" % (socket.inet_ntoa(pkt.src), socket.inet_ntoa(pkt.dst))

if __name__ == '__main__':
    pass

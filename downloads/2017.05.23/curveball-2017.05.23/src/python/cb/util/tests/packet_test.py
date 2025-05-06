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

""" Please run nosetests on this directory to run the tests in this file. """
    
import time
import binascii as bin
import sys
import struct

sys.path.append('../../../')
from cb.util.packet import Packet

tlspkt = '45000093dcf600003406c3a7480ecc67805950f801bbe7b8bdb8019aa72449c8801800c2b8b000000101080a444e983d0b635adb170301005a0dad99086fe9236b7c79ebd63b30b4b38d0e8b68451d00b6a3463457c3b176d4e1ed732361b4c1c1b31a1f7d3f2661ca5d70d6a0dc39376ec73519233c8a95154ae43d765e8cb4b1b9a49067f7793c1b5b4bb32d02826f4219a2'
tlspayload = '170301005a0dad99086fe9236b7c79ebd63b30b4b38d0e8b68451d00b6a3463457c3b176d4e1ed732361b4c1c1b31a1f7d3f2661ca5d70d6a0dc39376ec73519233c8a95154ae43d765e8cb4b1b9a49067f7793c1b5b4bb32d02826f4219a2'
tlspkt = bin.unhexlify(tlspkt)
tlspayload= bin.unhexlify(tlspayload)

def load_test():
    p = Packet(tlspkt)

def tcp_test():
    p = Packet(tlspkt)
    assert(p.protocol == 6)
    
def ip_attrib_test():
    p = Packet(tlspkt)
    assert(p.get_src() == '\x48\x0E\xCC\x67')
    assert(p.get_dst() == '\x80\x59\x50\xF8')
    assert(p.get_ip_cksum() == 0xc3a7)
    assert(p.protocol == 6)

def payload_test():
    p = Packet(tlspkt)
    payload = p.get_payload()
    assert(payload == tlspayload)

def tcp_attrib_test():
    p = Packet(tlspkt)
    assert(p.get_sport() == 443)
    assert(p.get_dport() == 59320)
    assert(p.get_tcp_cksum() == 0xb8b0)
    assert(p.thl == 32 )
    assert(p.get_opts() == '\x01\x01\x08\x0a\x44\x4e\x98\x3d\x0b\x63\x5a\xdb')
    assert(p.get_payload_len() == 95)
    assert(p.get_seq() == 0xbdb8019a)
    assert(p.get_ack() == 0xa72449c8)
    assert(p.get_flags() == 0x18)

    old_seq = p.get_seq()
    p.set_seq(old_seq + 1)
    assert(p.get_seq() == old_seq + 1)
    assert(p.get_ack() == 0xa72449c8)
    old_ack = p.get_ack()
    p.set_ack(old_ack + 1)
    assert(p.get_ack() == old_ack + 1)
    

def ip_cksum_test():
    p = Packet(tlspkt)
    before = p.get_ip_cksum()
    p.update_cksum()
    after = p.get_ip_cksum()
    assert(before == after)


def tcp_cksum_test():
    p = Packet(tlspkt)
    before = p.get_tcp_cksum()
    p.update_cksum()
    after = p.get_tcp_cksum()
    assert(before == after)
    
def tcp_timestamp_test():
    p = Packet(tlspkt)
    (bef_tsval, _, _) = p.parse_timestamp()
    p.offset_timestamp(4, True)
    (after_tsval, _, _) = p.parse_timestamp()
    assert(bef_tsval + 4 == after_tsval)
    
    # Verify the TCP checksum
    before = p.get_tcp_cksum()
    p.update_cksum()
    after = p.get_tcp_cksum()
    assert(abs(after - before) == 4)


#def speed_test():
#    tstart = time.time()
#    num = 10000
#    for i in range(0,num):
#        p = pm.PktMangler(tlspkt)
#        # need to modify the packet, go for slow path
#        p.set_opts(p.get_opts() + p.get_opts())
#        p.to_str()
#    tend = time.time()
#    # Nose tests will hide the stdout unless you use -s flag
#    print "Can process %f packets per second" % ( float(num) / (tend-tstart))

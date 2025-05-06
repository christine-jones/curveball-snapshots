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



import dpkt
import optparse
import socket


def main():

    try:
        f = open("./misc/tls.packet", 'r')
    except:
        print 'Failed to open packet file: %s' % ("./misc/tls.packet")
        return

    # Read/parse packet.
    try:
        pkt = dpkt.ip.IP(f.read())
    except dpkt.UnpackError:
        print 'Error parsing packet.'
        return

    # Update the source/destination IP addresses.
    pkt.src = socket.inet_aton("10.1.1.2")
    pkt.dst = socket.inet_aton("10.1.2.3")

    # Create and configure socket.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))

    # Send the packet.
    dst_addr = "\x00\x04\x23\xc7\xa6\x34"
    src_addr = "\x00\x04\x23\xc7\xa8\x0e"
    ethertype = "\x08\x00"
    payload = pkt.pack()
    checksum = "\x00\x00\x00\x00"

    while 1:
        s.send(dst_addr+src_addr+ethertype+payload+checksum)


if __name__ == '__main__':
    exit(main())

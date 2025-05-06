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


import os
import dpkt
import socket

from cb.util.dpkt_util import dpkt_to_str
from cb.util.asyntun import AsynTUN
from asyncorebbn import asyncore
from dumbnet import ip_aton


"""
app1 <-> tun0 <-> forwarding <-> tun1 <-> app2

App1 wishes to speak with app2, but to do so
it connects to the forwarding engine, which rewrites
the dst to app2's IP, and writes the packet to tun1.

"""

tun0 = None
tun1 = None

def tun0rd(pkt):
    print "tun0 got: %s" % dpkt_to_str(pkt)
    # client -> server
    if pkt.dst == ip_aton('10.0.1.42'):
        pkt.src = ip_aton('10.0.1.84')
        pkt.dst = ip_aton('10.0.1.1')
    # server -> client
    elif pkt.dst == ip_aton('10.0.1.84'):
        pkt.src = ip_aton('10.0.1.42')
        pkt.dst = ip_aton('10.0.1.1')
        
    pkt.data.sum = 0
    pkt.sum = 0
    
    print "writing to tun0: %s" % dpkt_to_str(pkt)
    os.write(tun0.fd, str(pkt))

#def tun1rd(pkt):
#    print "tun1 got: %s" % dpkt_to_str(pkt)
#
#    pkt.src = ip_aton('10.0.1.42')
#    pkt.dst = ip_aton('10.0.1.1')
#    pkt.sum = 0
#    os.write(tun0.fd, str(pkt))
    
class EchoClient(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host,port))
        self.count = 0
    def handle_write(self):
        self.send("%d" % self.count)
        self.count += 1
    def handle_read(self):
        data = self.recv(8192)
        print "Received: %s" % data
        
class EchoHandler(asyncore.dispatcher_with_send):

    def handle_read(self):
        data = self.recv(8192)
        if data:
            self.send(data)


class EchoServer(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            print 'Incoming connection from %s' % repr(addr)
            handler = EchoHandler(sock)


def main():
    global tun0, tun1
    tun0 = AsynTUN(tun0rd, interface='tun0', ip='10.0.1.1', netmask='255.255.255.0')
    #tun1 = AsynTUN(tun1rd, interface='tun1', ip='10.0.2.1', netmask='255.255.255.0')
    
    server = EchoServer('10.0.1.1', 6000)
    # Must connect to some IP on tun0's net that isn't tun0's IP
    # so that it goes to the tun device which will turn it around
    # to 10.0.2.1
    client = EchoClient('10.0.1.42', 6000) 
    
    asyncore.loop()

#    def __init__(self, callback, interface='tun0', ip=None, netmask='255.255.255.0', omap=None):

if __name__ == '__main__':
    main()

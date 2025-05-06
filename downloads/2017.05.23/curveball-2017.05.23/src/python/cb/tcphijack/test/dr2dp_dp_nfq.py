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


import nfqueue
import socket
import dpkt
import cb.util.asyn_nfqueue
import logging

class DR2DP_DP_NFQ(object):
    def __init__(self, ):
        self.nfq = cb.util.asyn_nfqueue.AsynNFQueue(lambda c,payload: self.handle_read(payload))
        self.raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.log = logging.getLogger('cb.tcphijack')
        
    def set_read_callback(self, cb):
        self.read_callback = cb

    def register_cm(self, con_mon):
        self.con_mon = con_mon
        
    def handle_read(self, payload):
        data = payload.get_data()
    
        try:
            pkt = dpkt.ip.IP(data)
            self.log.debug("Forwarding pkt, window size: %d", pkt.data.win)

        except:
            # Can't parse it, let the kernel deal with it
            payload.set_verdict(nfqueue.NF_ACCEPT)
            return
        self.log.debug("Received from QUEUE: %s", cb.util.dpkt_util.dpkt_to_str(pkt))


            
        payload.set_verdict(nfqueue.NF_DROP)
        self.con_mon.forward_c2d(pkt)
                        
    def forward_d2c(self, pkt):
        self.raw.sendto(str(pkt), (sock.inet_ntoa(pkt.dst), 0))    

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
import logging
import socket
from dumbnet import ip_aton, ip_ntoa
import cb.util.twistedtun
from cb.util.dpkt_util import dpkt_to_str

class DR2DP_DP_TUN(object):
    def __init__(self, config):#interface, tunip, tun_mask, tun_decoy_dest):        
        self.config = config
        self.log = logging.getLogger('cb.tcphijack.dr2dp_dp_tun')
        self.tun = cb.util.twistedtun.TwistedTUN(lambda x: self.handle_read(x), 
                                           interface=self.config['test']['tun_interface'], 
                                           ip=self.config['test']['tun_ip'],
                                           netmask=self.config['test']['tun_netmask'])
        self.decoy_dest = ip_aton(self.config['test']['decoy_dest'])
        self.decoy_tun_dest = ip_aton(self.config['test']['decoy_tun_dest'])
        self.tun_ip = ip_aton(self.config['test']['tun_ip'])
        
        self.raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        self.flows = {}
        
        
    def register_cm(self, con_mon):
        self.con_mon = con_mon  

        
                      
        
    def handle_read(self, pkt):
        # client -> destination, convert the IP from
        # the tun device to the covert destination

        if pkt.src == self.tun_ip:
            pkt.dst = self.decoy_dest
            pkt.src = self.decoy_tun_dest
            pkt.sum = 0
            pkt.data.sum = 0
            
            flow = (pkt.src, pkt.data.sport, pkt.dst, pkt.data.dport)

            if flow in self.flows:
                self.log.debug("Sending to con mon: %s", dpkt_to_str(pkt))           
                self.con_mon.forward_c2d(str(pkt))
                
            if pkt.data.data and len(pkt.data.data) >= 4 and pkt.data.data[:4] =='\xDE\xAD\xBE\xEF':
                self.flows[flow] = True
                self.log.debug("Sending to con mon: %s", dpkt_to_str(pkt))           
                self.con_mon.forward_c2d(str(pkt))
            else:
                self.log.debug("Sending to raw device: %s", dpkt_to_str(pkt))
                self.raw.sendto(str(pkt), (ip_ntoa(pkt.dst), 0))
            
        elif pkt.src == self.decoy_dest:
            pkt.dst = self.tun_ip
            pkt.src = self.decoy_tun_dest
            pkt.sum = 0
            pkt.data.sum = 0
            self.log.debug("Sending to client: %s", dpkt_to_str(pkt))
            self.raw.sendto(str(pkt), (ip_ntoa(pkt.dst), 0))
            
               
    def forward_d2c(self, pkt):
        self.forward(pkt)
                 
    def forward(self, pkt):
        """ Act like a decoy router.  Forward here means
        you should get the packet to the destination, which
        could either be the decoy dest or the client """
        self.log.debug("FWD Sending: %s", dpkt_to_str(pkt))
        self.raw.sendto(str(pkt), (ip_ntoa(pkt.dst), 0))
         

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

import sys
sys.path.append('../python')
sys.path.append('../python/nfqueue/python')

from asyncorebbn import asyncore

import cb.util.cblogging
import cb.tcphijack.test.dr2dp_dp_nfq

import cb.tcphijack.c2d_nat
import cb.tcphijack.connection_monitor
import cb.tcphijack.d2c_nat
import cb.tcphijack.ccp_dumb
import cb.util.state
import cb.util.asyn_nfqueue

"""
Tests that TCP Hijacking works in the DP

Uses a dumb connection monitor (resets upon first payload in a flow)
Uses a dumb CCH (always sends to a fixed covert dest addr & port)

This program (dp_tcphijack) should run on a router

src - router - dst1
            \- dst2
            
Packets from the src nic (e.g. eth3) should be sent to NF QUEUE 0
e.g. sudo iptables -A FORWARD -i eth3 -j QUEUE

Configuring:
1. Open cch_dumb.py and change the covert destination's COVERT_PORT
   and COVERT_HOST values to match your dst2

Running:
1. router: 'sudo ./dp_tcphijack' 
2. src: 'ping dst1_ip_addr' to make sure forwarding is working
3. dst1: 'nc -l 4444' 
5. dst2: 'nc -l 6666'
6. src: 'cat (some file) | nc dst1_ip_addr 4444'

Result:
dst1's nc should be reset and the text should have gone to dst2 instead.
"""

    



def main():
    dr2dp = cb.tcphijack.test.dr2dp_dp_nfq.DR2DP_DP_NFQ()

    state = cb.util.state.State()
    ingress_nat = cb.tcphijack.c2d_nat.C2DNat(state)
    conn_monitor = cb.tcphijack.connection_monitor.ConnectionMonitor(state, ingress_nat, dr2dp)
    _ = cb.tcphijack.d2c_nat.D2CNat(state, conn_monitor, ingress_nat)
    _ = cb.tcphijack.ccp_dumb.CCP_DP(state, conn_monitor)
        
    
    asyncore.loop()



if __name__ == "__main__":
    main()



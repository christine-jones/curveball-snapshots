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


import cb.tcphijack.c2d_nat as c2d_nat
import StringIO
import binascii
import dpkt
from cb.tcphijack.connection_monitor import FlowInfo
from cb.util.state import State

#pkt = 450000b45d6240003f06c7cd0a00000a0a00020b822101bbdd2177fb50d753da801800ba6c5000000101080a03412d1003412d102d189cd4899b6eff43a6a9a64be91ec098595b0233b201113d44ac688fdcdf50c2261bf2968dae91de4c847d665670369042a7cfc49309929fd7a00c882cb934d404c28d4bf708b3c45c04f1d388cf424b2fe3da50703a8527f6a6e4998a15e135fd5f6aadb8c7c3e18e2aa565f55d86b3675a0173b26378284dc138c40d98ec
#snat_tuple = 0a648001, 100, 0a640001, 56907
#seq_off = 2696747830
#ts_off = 0
outpkt = '450000b45d6240003f0649180a6480010a6400010064de4bdd2177fbf1946f10801800bad6d300000101080a03412d1003412d102d189cd4899b6eff43a6a9a64be91ec098595b0233b201113d44ac688fdcdf50c2261bf2968dae91de4c847d665670369042a7cfc49309929fd7a00c882cb934d404c28d4bf708b3c45c04f1d388cf424b2fe3da50703a8527f6a6e4998a15e135fd5f6aadb8c7c3e18e2aa565f55d86b3675a0173b26378284dc138c40d98ec'


class C2DNAT_test(object):
    
    def __init__(self):
        # Write the resulting bytes to stdout        
        self.out_buff = StringIO.StringIO()
        state = State()
        state.engine_fd = self.out_buff

        self.c2d_nat = c2d_nat.C2DNat(state)
        

    def forwardc2d_test(self):
        flow_info = FlowInfo(None)
        flow_info.snat_tuple = (binascii.unhexlify('0a648001'),
                                    100,
                                    binascii.unhexlify('0a640001'),
                                    56907)
        flow_info.seq_offset = 2696747830
        flow_info.ts_offset = None
        
        pkt = '450000b45d6240003f06c7cd0a00000a0a00020b822101bbdd2177fb50d753da801800ba6c5000000101080a03412d1003412d102d189cd4899b6eff43a6a9a64be91ec098595b0233b201113d44ac688fdcdf50c2261bf2968dae91de4c847d665670369042a7cfc49309929fd7a00c882cb934d404c28d4bf708b3c45c04f1d388cf424b2fe3da50703a8527f6a6e4998a15e135fd5f6aadb8c7c3e18e2aa565f55d86b3675a0173b26378284dc138c40d98ec'
        pkt = binascii.unhexlify(pkt)
        pkt = dpkt.ip.IP(pkt)

        self.c2d_nat.forward_c2d(pkt, flow_info)

        self.out_buff.seek(0)
        out = self.out_buff.read(3000)
        hexout = binascii.hexlify(out)

        assert(hexout == '450000b45d6240003f0649180a6480010a6400010064de4bdd2177fbf1946f10801800bad6d300000101080a03412d1003412d102d189cd4899b6eff43a6a9a64be91ec098595b0233b201113d44ac688fdcdf50c2261bf2968dae91de4c847d665670369042a7cfc49309929fd7a00c882cb934d404c28d4bf708b3c45c04f1d388cf424b2fe3da50703a8527f6a6e4998a15e135fd5f6aadb8c7c3e18e2aa565f55d86b3675a0173b26378284dc138c40d98ec')
    
    

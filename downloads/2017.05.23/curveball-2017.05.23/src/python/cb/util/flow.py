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

#import dumbnet as dnet
import socket


def get_flow(pkt, dir="c2d"):
    """ get_flow: given a dpkt, return the flow 4-tuple """
    flow =  (pkt.src, pkt.data.sport, pkt.dst, pkt.data.dport)    
    if dir == "d2c":
        return (flow[2],flow[3],flow[0],flow[1])
    else:
        return flow

def flow_to_str((src, sport, dst, dport)):
    """ flow_to_str: given a flow 4-tuple, return the binary form """
    return '%s:%d %s:%d' % (socket.inet_ntoa(src), sport, socket.inet_ntoa(dst), dport)

if __name__ == '__main__':
    pass

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

# Ingress  = Packets coming from the decoy router (say from the client)
# Egress   = Packets on their way to the decoy router (say from the covert dest)

from cb.util import free_src
import cb.util.free_src


class Hijack(object):
    """ Hijack - Stores state pertaining
    to a single hijack """
    
    def __init__(self):
        self.state = None
        self.client_flow = None
        self.engine_flow = None
        self.queue = []
        self.seq_offset = None
        self.sentinel = None
    

class State(object):
    '''State
    
    This object is meant to be passed to the constructor of each DP module.
    Since the DP is single-threaded access to the state object does not
    need to be mutex protected.
    
    Attributes:
    @var client_flows: dict from client 4-tuple (c2d direction) to hijack object
    @var engine_flows: dict from engine 4-tuple (c2d direction) to hijack object
    @var enginge_fd: file descriptor of TUN device
    '''


    def __init__(self):
        '''
        Constructor        
        '''

        self.client_flows = {}
        self.engine_flows = {}
        self.engine_fd = None
        
        
    def create_hijack(self, flow, state):
        """create_hijack: To be called from connection monitor.
        
        Creates and returns a hijack, also configuring the client
        flow to point at the new hijack object """
        hijack = Hijack()
        hijack.client_flow = flow
        hijack.state = state
        self.client_flows[flow] = hijack        

        return hijack
    

                
        
    
    def set_engine_flow(self, hijack, engine_flow):
        """ set_engine_flow: for a hijack, set the engine_flow
        and point the engine_flows[engine_flow] at the hijack """
        
        hijack.engine_flow = engine_flow
        self.engine_flows[engine_flow] = hijack
        
    
    def get_hijack(self, flow):
        """ Search in client and engine flows
        for this hijack given a c2d directed 4-tuple """
        if flow in self.client_flows:
            return self.client_flows[flow]
        elif flow in self.engine_flows:
            return self.engine_flows[flow]
        return None

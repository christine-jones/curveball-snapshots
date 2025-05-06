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
from asyncorebbn import asyncore
import ipaddr
import nfqueue




class AsynNFQueue(asyncore.file_dispatcher):
    """An asyncore dispatcher of nfqueue events.  
                                                               
    The nfqueue module will invoke a callback function once
    a packet has been read.  We simply tell asyncore what the 
    file descriptor is for nfqueue and then once it's ready to 
    be read we call nfqueue's process_pending function, which 
    in turn calls our callback.
    
    Attributes:
        fd: The file descriptor for nfqueue        
                                                                                  
    """
    
    def __init__(self, callback, nqueue=0, family=socket.AF_INET, 
                 maxlen=5000, map=None):
        self.queue = nfqueue.queue()
        self.queue.set_callback(callback)
        self.queue.fast_open(nqueue, family)
        self.queue.set_queue_maxlen(maxlen)
        self.fd = self.q.get_fd()
        asyncore.file_dispatcher.__init__(self, self.fd, map)
        self.queue.set_mode(nfqueue.NFQNL_COPY_PACKET)
    
    def handle_read(self):
        #print "Processing at most 5 events"
        self.queue.process_pending(5)
    
    # We don't need to check for the socket to be ready for writing               
    def writable(self):
        return False
    


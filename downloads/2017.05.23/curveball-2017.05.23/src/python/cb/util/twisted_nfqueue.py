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

from zope.interface import implements
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import socket
import os
import sys
sys.path.append('../python/nfqueue')
import nfqueue




class TwistedNFQueue(object):
    implements(IReadDescriptor)    
    """A twisted dispatcher of nfqueue events.  
                                                               
    The nfqueue module will invoke a callback function once
    a packet has been read.  We simply tell twisted what the 
    file descriptor is for nfqueue and then once it's ready to 
    be read we call nfqueue's process_pending function, which 
    in turn calls our callback.
    
    Attributes:
        fd: The file descriptor for nfqueue        
                                                                                  
    """
    
    def __init__(self, callback, nqueue=0, family=socket.AF_INET, 
                 maxlen=5000, map=None):

        self.queue = nfqueue.queue()
        self.queue.open()
        self.queue.bind(family)
        self.callback = callback
        self.queue.set_callback(callback)
        #self.queue.destroy_queue(nqueue)
        self.queue.create_queue(nqueue)
        self.queue.set_queue_maxlen(5000)

        self.fd = self.queue.get_fd()
        self.queue.set_mode(nfqueue.NFQNL_COPY_PACKET)
        reactor.addReader(self)

        
    def fileno(self):
        return self.fd

    def logPrefix(self):
        return 'TwistedNFQueue'
    
    def doRead(self):
        self.queue.process_pending(5)
    
    def connectionLost(self, reason):
        pass
    
    def close(self):
        print "Unbinding in closes"
        reactor.removeReader(self)
        self.queue.unbind(socket.AF_INET)
        self.queue.close()
                
    def __del__(self):
        """ If the object dies, remove the reader for the reactor
        and clean up the fd if it's still open """
        print "Unbinding in __del__"
        reactor.removeReader(self)
        #self.queue.unbind(socket.AF_INET)
        #self.queue.close()
    

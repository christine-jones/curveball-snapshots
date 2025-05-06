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
import fcntl
import struct
import dpkt
from asyncorebbn import asyncore

class AsynTUN(asyncore.file_dispatcher):
    """The TUN asyncore dispatcher
    
    This class creates a TUN device and registers its
    file descriptor with asyncore.  Then, when the fd is
    ready for reading, handle_read is called which invokes
    a callback.
    
    Attributes:
        fd: the TUN file descriptor
    """

    def __init__(self, callback, interface='tun0', ip=None, 
                 netmask='255.255.255.0', omap=None):
        """ Constructor
        
        Creates the TUN device, sets the file descriptor, and calls
        asyncore's init function with the descriptor.
        
        Parameters:
            callback: The callback function (that takes a single pkt argument) to call when a 
                dpkt has been read
            interface: The name of the TUN interface to create
            ip: The IP address to give the interface
            netmask: The netmask to configure for the interface
        """
        tunsetiff   = 0x400454ca
        tunsetowner = tunsetiff + 2
        iff_tun     = 0x0001
        iff_no_pi = 0x1000
        self.callback = callback
        tun = os.open("/dev/net/tun", os.O_RDWR)    
        fcntl.ioctl(tun, tunsetiff, struct.pack("16sH", interface, iff_tun | iff_no_pi))
        fcntl.ioctl(tun, tunsetowner, 1000)        
        if not ip is None:
            os.popen("ifconfig %s %s netmask %s" % (interface, ip, netmask))
            
        self.fd = tun
        self.log = logging.getLogger('cb.tcphijack')
        asyncore.file_dispatcher.__init__(self, self.fd, omap)
        

    
    def handle_read(self):
        pkt = dpkt.ip.IP(os.read(self.fd, 9000))
        self.callback(pkt)

    # We don't need to check for the socket to be ready for writing               
    def writable(self):
        return False

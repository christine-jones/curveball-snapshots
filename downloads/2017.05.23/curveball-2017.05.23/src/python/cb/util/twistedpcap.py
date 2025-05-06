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

import pcap

from twisted.internet import abstract

class TwistedPcap(abstract.FileDescriptor):
    def __init__(self, callback, dev, filter):


        abstract.FileDescriptor.__init__(self)

        p = pcap.pcapObject()
        p.open_live(dev, 1600, 0, 100)
        p.setfilter(filter, 0, 0)        
        p.setnonblock(1)

        self.fn = p.fileno()
        self.pcap = p
        self.callback = callback
        self.startReading()

    def fileno(self):
        return self.fn

    def doRead(self):
        self.pcap.dispatch(10, self.callback)

    def connectionLost(self, reason):
        pass

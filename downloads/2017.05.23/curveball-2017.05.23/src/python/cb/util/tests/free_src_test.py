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

import nose.tools

import cb.util.free_src as fs



class FreeSrc_test(object):
    def overflow_test(self):
        nose.tools.assert_raises(fs.InsufficientNetAddresses, lambda: fs.FreeSrc('10.0.128.0/30', 1000000))
        assert(fs.FreeSrc('10.0.128.0/30', 30000))
        
    def itotuple_test(self):
        c = fs.FreeSrc('10.0.128.0/24', 100000)
        (ip,port) = c.itotuple(0)
        assert((ip,port) == ('10.0.128.1', 1025))
        
        (ip,port) = c.itotuple(1)        
        assert((ip,port) == ('10.0.128.1', 1026))
        
        (ip,port) = c.itotuple(len(c.ports))
        assert((ip,port) == ('10.0.128.2', 1025))

        (ip,port) = c.itotuple(len(c.ports)-1)
        assert((ip,port) == ('10.0.128.1', 65535))
    
    def tupletoi_test(self):
        c = fs.FreeSrc('10.0.128.0/24', 100000)
        assert(c.tupletoi(('10.0.128.1', 1025)) == 0)        
        assert(c.tupletoi(('10.0.128.1', 1026)) == 1)       
        assert(c.tupletoi(('10.0.128.2', 1025)) == len(c.ports))        
        assert(c.tupletoi(('10.0.128.1', 65535)) == len(c.ports)-1)
        
        assert(c.tupletoi(c.itotuple(12314)) == 12314)
    
    def alloc_src_test(self):
        c = fs.FreeSrc('10.0.128.0/24', 100000)
        bef = len(c.free_list)
        (ip1,port1) = c.alloc_src()
        (ip2,port2) = c.alloc_src()
        aft = len(c.free_list)
        assert(bef == aft + 2)
        
    
    def free_src_test(self):
        c = fs.FreeSrc('10.0.128.0/24', 100000)
        bef = len(c.free_list)
        (ip1,port1) = c.alloc_src()
        (ip2,port2) = c.alloc_src()
        c.free_src((ip1,port1))
        c.free_src((ip2,port2))
        
        aft = len(c.free_list)
        assert(bef == aft)

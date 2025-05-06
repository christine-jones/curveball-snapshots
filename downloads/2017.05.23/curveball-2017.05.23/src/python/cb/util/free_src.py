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

import ipaddr
import random

class FreeListEmpty(Exception):
    pass

class InsufficientNetAddresses(Exception):
    pass

class FreeIPv4Addr(object):
    """ FreeIPv4Addr: manages free IPv4 addresses from a subnet """

    def __init__(self, src_net, requested_addrs, omitted_addrs=None,
            shuffle=False):
        """
        src_net: the IPv4 subnet, given in the format used by the
            ipaddr library.  This requires a full dotted quad, even
            if some of the elements are unused.  For example, it's
            NOT OK to say 10/8; it is required to say 10.0.0.0/8.

            src_net is not sanity-checked.

        requested_addrs: the number of addresses requested.  If the
            subnet is not large enough to provide that many addresses,
            as many as possible are allocated.  The field self.max_addrs
            tells the caller the maximum number of addresses available.

            Note that the host prefix and broadcast address are always
            removed from the set of addresses.  In some cases it may be
            desirable to remove other addresses (such as a gateway address); 

        omitted_addrs: a set of addresses to omit from the set of free
            addresses.  For example, to omit a gateway address, simply
            include it in this list.  Note that this list is not
            sanity-checked; it could contain nonsense values, or addresses
            that are not in the src_net.

        shuffle: periodically shuffle the free list to make the order in which
            addresses are chosen more random.

        """

        if not omitted_addrs:
            omitted_addrs = []

        self.net = ipaddr.IPv4Network(src_net)

        # Figure out if this src_net can provide the requested number of
        # addrs, and adjust if necessary.  We can't allocate the
        # subnet address prefix itself, or the broadcast address, so the total
        # space is two smaller than the size of the hostmask. (it's typical to
        # reserve additional addresses for things like the subnet gateway, but
        # we do not do that here) 
        #
        # We could raise an exception when the network is smaller than the
        # requested_addrs, but we don't.  The caller can compare the
        # requested_addrs with max_addrs provided and decide what to do.
        #
        free_addrs = (1 << (32 - self.net.prefixlen)) - 2
        if (free_addrs - len(omitted_addrs)) < requested_addrs:
            self.max_addrs = free_addrs - len(omitted_addrs)
        else:
            self.max_addrs = requested_addrs

        # If there aren't enough addresses to go around...
        #
        # TODO: this is a graceless way of handling this error.
        #
        if self.max_addrs < 0:
            self.max_addrs = 0

        self.addrs = [str(self.net[i])
                for i in range(0, self.max_addrs + len(omitted_addrs) + 1)
                if not str(self.net[i]) in omitted_addrs]

        # If the omitted addresses were bogus or duplicated, then there
        # might be extra addresses on the send of self.addr (corresponding
        # to the addresses that weren't omitted).  Chop them off.
        #
        if len(self.addrs) > self.max_addrs:
            self.addrs = self.addrs[:self.max_addrs]

        # addrs_rev is a reverse lookup dict: given an address, find the index
        # of that address in the addrs list.
        #
        self.addrs_rev = {}
        for i in range(0, self.max_addrs):
            self.addrs_rev[self.addrs[i]] = i

        self.free_list = range(self.max_addrs)

        self.shuffle_mode = shuffle
        self.ops_since_shuffle = 0
        self.shuffle_threshold = 5 # FIXME: guesstimate

        if self.shuffle_mode:
            self.shuffle()

    def shuffle(self):
        """
        If shuffle mode is enabled, then shuffle the free list in order to
        make the order of addresses returned more difficult to anticipate.
        
        In order to limit the overhead of this operation, we don't do it for
        every free/alloc, but try to limit it the
        frequency.  This can backfire for very small freelists.
        """

        if not self.shuffle_mode:
            return

        self.ops_since_shuffle += 1

        if self.ops_since_shuffle > self.shuffle_threshold:
            random.shuffle(self.free_list)
            self.ops_since_shuffle = 0

    def alloc(self):
        """
        Allocate an IPv4 address.

        TODO: we should do something meaningful if alloc fails.
        """

        self.shuffle()

        index = self.free_list.pop(0)

        return self.addrs[index]

    def free(self, addr):
        """
        Deallocate an IPv4 address, making it available for reallocation.

        TODO: we should do something meaningful if given a bogus addr
        to free.  For example, freeing the same addr twice means that it
        can then be alloc'd twice, which would be a disaster.
        """

        index = self.addrs_rev[addr]

        self.free_list.append(index)


class FreeSrc(object):
    """ FreeSrc: Manages free addresses/ports
    
    The purpose of the FreeSrc class is to manage a free-list
    of available (port, IP addr) pairs on a given network
    """
    
    def __init__(self, src_net, max_connections):
        self.free_list = range(max_connections)
        self.net = ipaddr.IPv4Network(src_net)
        self.ports = range(1025,65536)
        self.ips = []
        num_ips = max_connections / len(self.ports) + 1
        if num_ips > (self.net.numhosts - 2):
            raise InsufficientNetAddresses()
            
        for i in range(1, num_ips + 1):
            self.ips.append(str(self.net[i]))
            
    def itotuple(self, i):
        ip = self.ips[i / len(self.ports)]
        port = self.ports[i % len(self.ports)]
        return (ip, port)
    
    def tupletoi(self, (ip, port)):
        ip_num = int(ipaddr.IPv4Address(ip)) - int(ipaddr.IPv4Address(self.ips[0]))
        index = len(self.ports) * ip_num + port - 1025

        return index

    def alloc_src(self):
        i = self.free_list.pop(0)
        return self.itotuple(i)
    
    def free_src(self, (addr,port)):
        i = self.tupletoi((addr,port))
        self.free_list.append(i)

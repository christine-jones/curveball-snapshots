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

"""
Routines to construct a set of sentinels, add, delete, and query the set.
"""

import logging

import cb.util.cblogging

# todo:
# add exception handling and usage block

# sentinel file is assumed to be formatted as one sentinel per line,
# followed by an optional "key name" (kname) corresponding to the
# name of the key that was used to create that sentinel.

class CheckSentinel(object):
    """
    load 6.4M and lookup 6.405M sentinels in 17.5s on 2.66 GHz Core i7
    """

    def __init__(self, sentinel_file=None):
        """
        Import sentinels into a dictionary
        """
        self.logger = logging.getLogger('cb.noc')
        #self.sentinels = set()
	# Make self.sentinels a dictionary
        self.sentinels = dict()

        # dicts to record the kname of the key used to generate
        # each sentinel prefix, and which sentinel prefixes are
        # associated with a given kname.
        #
        self.sentinel_prefix2kname = dict()
        self.kname2sentinel_prefixes = dict()

        if sentinel_file:
            self.add_file(sentinel_file)

    def __contains__(self, sentinel_prefix):
        """ 
        Test if key is in dictionary

        >>> a = CheckSentinel(file)
        >>> "xyzzy" in a
        False
        """       

        state = sentinel_prefix in self.sentinels
        return state

    def __getitem__(self, key):
        """
        Return value indexed by key in dictionary, self.sentinels[key]
        Raises a KeyError is key in not in dictionary
        
        """
        try:
            value = self.sentinels[key]
        except KeyError:
            raise
        return value

    def add_file(self, fname):
        """
        Add all of the sentinels in the file with the given fname
        to the set of sentinels.
        """
        self.logger.debug('______in CheckSentinel.add_file(%s)' % (fname,))
        for line in open(fname, 'r'):
            self.logger.debug('______reading %s from %s', line, fname)
            fields = line.split()
            sentinel = fields[0]

            # if there's a kname, then record the related info.
            if len(fields) > 1:
                kname = fields[1]
            else:
                kname = None

            self.add(sentinel, kname)

    def delete_file(self, fname):
        """
        Discard all of the sentinels in the file with the given fname
        from the set of sentinels.
	Currently discards silently.
        """

        for line in open(fname, 'r'):
            fields = line.split()
            sentinel = fields[0]

            self.delete(sentinel)

    def add(self, sentinel, kname=None):
        """
        Add another sentinel.
        """

        sent_64 = sentinel[:16]
        sent_128 = sentinel[:32]

        # if there's a kname, then record the related info.
        if kname:
            self.sentinel_prefix2kname[sent_64] = kname
            self.sentinel_prefix2kname[sent_128] = kname

            if not kname in self.kname2sentinel_prefixes:
                self.kname2sentinel_prefixes[kname] = set()
            self.kname2sentinel_prefixes[kname].add(sent_64)
            self.kname2sentinel_prefixes[kname].add(sent_128)

	# load tls sentinel (64 bit) as key with remaining bits as value
        self.sentinels[sent_64] = sentinel[16:]
	# load http sentinel (128 bit) as key with remaining bits as value
        self.sentinels[sent_128] = sentinel[32:]

    def delete(self, sentinel):
        """
        Drop a sentinel; fail silently if the sentinel is not present.
        """

        sent_64 = sentinel[:16]
        sent_128 = sentinel[:32]

        if sent_64 in self.sentinel_prefix2kname:
            kname = self.sentinel_prefix2kname[sent_64]

            self.sentinel_prefix2kname.pop(sent_64)
            self.sentinel_prefix2kname.pop(sent_128)

            self.kname2sentinel_prefixes[kname].discard(sent_64)
            self.kname2sentinel_prefixes[kname].discard(sent_128)

	# remove tls sentinel
        self.sentinels.pop(sent_64, None)
	# remove http sentinel
        self.sentinels.pop(sent_128, None)

    def get(self, sentinel_prefix):
        """
        Get the value stored with this sentinel prefix (either
        a 64-bit prefix for TLS, or 128-bit prefix for HTTP)

        returns the value stored or None if the prefix is not found
        """

        value = self.sentinels.get(sentinel_prefix)
        return value


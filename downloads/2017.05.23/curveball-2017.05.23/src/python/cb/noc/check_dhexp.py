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
Routines to construct and implement a sentinel_prefix -> DH exponent map.
"""

import logging

import cb.util.cblogging

# todo:
# add exception handling and usage block

# A dhexp file is assumed to be formatted as lines containing a
# sentinel prefix (16 hex digits), whitespace, and then a DH exponent
# (the client's private key) in the MSE group (which may be as many
# as 192 hex digits, but can be shorter).

class CheckDHexp(object):
    """
    Manages the sentinel_prefix -> DH exponent map.
    """

    def __init__(self, dhexp_file=None):
        """
        Import DH exponents into a dictionary
        """
        self.logger = logging.getLogger('cb.noc')
        self.sentinel_prefix2dhexp = dict()

        if dhexp_file:
            self.add_file(dhexp_file)

    def __contains__(self, sentinel_prefix):
        """
        Test if key is in dictionary
        """

        state = sentinel_prefix in self.sentinel_prefix2dhexp
        return state

    def __getitem__(self, sentinel_prefix):
        """
        Return value indexed by key in dictionary, self.sentinels[key].
        Raises an exception if the lookup fails.

        """
        return self.sentinel_prefix2dhexp[sentinel_prefix]

    def add_file(self, fname):
        """
        Add all of the sentinel-prefix -> dhexp maps in the file
        with the given fname to the dict.
        """

        print 'DHexp watcher adding [%s]' % fname

        for line in open(fname, 'r'):
            self.logger.debug('______reading %s from %s', line, fname)
            fields = line.split()
            sentinel_prefix = fields[0]

            # if the line is well-formed, add it.
            if len(fields) > 1:
                dhexp = fields[1]
                self.add(sentinel_prefix, dhexp)

    def delete_file(self, fname):
        """
        Discard all of the sentinels in the file with the given fname
        from the set of sentinels.
	Currently discards silently.
        """

        for line in open(fname, 'r'):
            fields = line.split()
            sentinel_prefix = fields[0]

            self.delete(sentinel_prefix)

    def add(self, sentinel_prefix, dhexp):
        """
        Add another sentinel_prefix -> dhexp map.
        """

        self.sentinel_prefix2dhexp[sentinel_prefix] = dhexp

    def delete(self, sentinel_prefix):
        """
        Drop a sentinel_prefix; fail silently if the sentinel_prefix
        is not present.
        """

        self.sentinel_prefix2dhexp.pop(sentinel_prefix, None)

    def get(self, sentinel_prefix):
        """
        Get the DH exponent for this sentinel prefix (if any)

        returns the value stored or None if the prefix is not found
        """

        value = self.sentinel_prefix2dhexp.get(sentinel_prefix)
        return value


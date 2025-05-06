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
Routines to test false positive rate on Bloom filter implementation

Reads sentinel file and determines hit rate.  If bloom filter made from
sentinel file, then all should hit.  If not, then hit rate should be 1e-6.
Since the sentinel files are small, hit rate should be 0.

"""
# Todo:
# Better Exception handling: now has none

import binascii
import os
import sys

sys.path.append('../../../python')

from cb.noc.cbbloom import CB_BloomFilter

if __name__ == '__main__':
    def main(argv):

        bf_file_name = sys.argv[1]
        bf_file = open(bf_file_name, 'r')
        bf = CB_BloomFilter.fromfile(bf_file)

        sent_file_name = sys.argv[2]
        sents = open(sent_file_name, 'r').readlines()

        fp_count = i = 0

        for testval in sents:
            i += 1
            if binascii.unhexlify(testval[0:16]) in bf:
                fp_count += 1
                print i, fp_count, fp_count/i, testval[0:16]
            i += 1
            if binascii.unhexlify(testval[0:32]) in bf:
                fp_count += 1
                print i, fp_count, fp_count/i, testval[0:32]
            if i % 100000 == 0:
                print i, fp_count, fp_count/i

    exit(main(sys.argv))

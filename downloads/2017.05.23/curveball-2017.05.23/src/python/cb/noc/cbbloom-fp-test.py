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
Routine to test false positive rate on Bloom filter implementation

"""

# Todo:
# Better Exception handling: now has none
# Check random values against real sentinels to confirm false positives
# Use data in out_file to recover and restart from last entry
# Select the length of the random values: now fixed at 8 bytes, the size
#   of the TLS (Bi and Uni) sentinels


import os
import sys
import binascii

sys.path.append('../../../python')

from cb.noc.cbbloom import CB_BloomFilter

if __name__ == '__main__':
    def main(argv):

        sentinel_byte_len = 8 # 8 bytes for TLS, 16 bytes for HTTP
        bf_file_name = sys.argv[1]

        with open(bf_file_name, 'r') as bf_file:
            bf = CB_BloomFilter.fromfile(bf_file)

        out_file_name = bf_file_name + '.fptest'
        if os.access(out_file_name, os.F_OK):
            print " ERROR: %s exists.  Exiting..." %  (out_file_name)
            exit()

        with open(out_file_name, 'a', 1) as out_file:
            out_file.write("%s\n%s\n" % (bf_file_name, bf))

            fp_count = i = 0

            while True:
                i += 1
                testval = os.urandom(sentinel_byte_len)
                if testval in bf:
                    fp_count += 1
                    out_file.write("%d %d %e %s\n" %
                                   (i, fp_count, float(fp_count)/i, binascii.hexlify(testval)))
                    out_file.flush()
                    os.fsync(out_file.fileno())

                if i % 1000000 == 0:
                    out_file.write ("%d %d %e\n" % (i, fp_count, float(fp_count)/i ))
                    # print "%d %d %e " % (i, fp_count, float(fp_count)/i)
                    out_file.flush()
                    os.fsync(out_file.fileno())

    exit(main(sys.argv))

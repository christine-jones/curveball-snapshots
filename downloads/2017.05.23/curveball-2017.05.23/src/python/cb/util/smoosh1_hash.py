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
A good hash function to use for sentinels.

Not as fast as the quickest, but has very good diffusion
properties.
"""

def smoosh1_hash(value, seed=0):
    """
    Returns a 32-bit hash of the value (which must be a string)
    starting with the given integer seed.
    """

    curr_seed = seed
    temp = 0
    chunks = len(value) / 4

    # We want the length to have a notable effect on the outcome;
    # some hash functions see a lot of collisions with prefixes.
    #
    # These constants were picked pseudo-randomly and there might
    # be better numbers.

    temp = len(value) * 0x18521031531
    temp &= 0xffffffffffffffff
    temp ^= 0x1e2093c89a0b
    temp ^= seed * 0x13467
    temp &= 0xffffffffffffffff

    offset = 0
    for i in xrange(chunks):
        offset = i << 2
        c_0 = 0x11 ^ ord(value[offset + 0])
        c_1 = 0x22 ^ ord(value[offset + 1])
        c_2 = 0x44 ^ ord(value[offset + 2])
        c_3 = 0x88 ^ ord(value[offset + 3])

        c_0 *= 0x00030509
        c_1 *= 0x09000301
        c_2 *= 0x05090003
        c_3 *= 0x03010900

        curr_seed += c_0 ^ c_1 ^ c_2 ^ c_3
        curr_seed &= 0xffffffffffffffff
        curr_seed += curr_seed << 3
        curr_seed &= 0xffffffffffffffff

        temp ^= curr_seed
        temp &= 0xffffffffffffffff

    # Deal with any leftover bytes
    #
    # This method is adequate for the things I'm hashing against, but
    # it isn't as strong as the main loop and could be improved.

    offset = chunks * 4

    for j in xrange(len(value) - offset):
        rem_c = ord(value[offset + j])

        rem_c ^= (0x11 << j)
        rem_c *= 0x03050901 << (j * 2);

        curr_seed += rem_c
        curr_seed += curr_seed << 3;

        temp ^= curr_seed
        temp &= 0xffffffffffffffff

    # Provoke avalanching by folding the bits over at different offsets
    #
    # These offsets were chosen by a combination of randomness and
    # trial and error: trying to keep them small enough so we don't
    # just shift info off into oblivion, but large enough so that
    # most bits have an opportunity to "interact" with the other bits.
    #
    # Someone with a better understanding of the theory might find
    # better constants (or fewer of them).

    sval = (temp << 16) & 0xffffffffffffffff
    temp ^= sval
    temp &= 0xffffffffffffffff

    temp += (temp >> 3)
    temp &= 0xffffffffffffffff

    sval = (temp << 8) & 0xffffffffffffffff
    temp ^= sval
    temp &= 0xffffffffffffffff

    temp += (temp >> 6)
    temp &= 0xffffffffffffffff
    temp ^= (temp << 4)
    temp &= 0xffffffffffffffff
    temp += (temp >> 12)
    temp &= 0xffffffffffffffff
    temp ^= (temp << 2)
    temp &= 0xffffffffffffffff
    temp += (temp >> 11)
    temp &= 0xffffffffffffffff
    temp ^= (temp << 1)

    # Even though we've been keeping 64 bits of state in temp,
    # only the bottom 32 is "good".  Don't try to use this
    # as a 64-bit hash...

    return temp & 0xffffffff

def smoosh1_hash_seeded(seed):
    """
    Return a closure for smoosh1_hash with the given seed.

    Useful if you want to create a suite of hash functions
    with different seeds.
    """
    def inner(data):
        return smoosh1_hash(data, seed)
    return inner


if __name__ == '__main__':
    import sys

    def test_main():
        """
        Read lines of the form 'X HASHX VALUEX SEEDX' (where HASHX is
        a 32-bit number expressed in hex, SEEDX is a 32-bit number
        expressed in hex, and VALUEX is an arbitrary string, also
        expressed in hex).  Then use smoosh1_hash to compute the
        hash of the string and the seed, and compare the result 
        with HASHX.  Prints diagnostics if there are any mismatches.

        The usual way of creating these lines is by running the hash
        tester for smoosh1_hash.cc (in src/click/curveball, compiled
        with -DTEST_MAIN).  That program creates input to pipe into
        this script.  If both implementations are functionally identical,
        then everything should match.
        """

        lines = sys.stdin.readlines()

        errcnt = 0

        for line in lines:
            (_, hash_hex, value_hex, seed_hex) = line.split()

            hash_bin = int(hash_hex, 16)
            seed_bin = int(seed_hex, 16)
            value_bin = value_hex.decode('hex')

            new_hash_bin = smoosh1_hash(value_bin, seed_bin)

            if new_hash_bin != hash_bin:
                print 'ERROR %.8x != %.8x' % (hash_bin, new_hash_bin)
                errcnt += 1

            print 'X %.8x %s %.8x' % (
                    smoosh1_hash(value_bin, seed_bin), value_hex, seed_bin)

        if errcnt:
            print 'ERRORS: %d mismatches' % errcnt
            return 1
        else:
            print 'Passed'
            return 0

    sys.exit(test_main())

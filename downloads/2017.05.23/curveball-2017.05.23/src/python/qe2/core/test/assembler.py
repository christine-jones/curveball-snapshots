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
Basic tests for qe2.core.assembler
"""

import sys

from qe2.core.assembler import Qe2Assembler

def test_add():

    # check that a segment prior to base is trimmed.
    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(0, 'XXXXefg')
    assert(asm.segments == [[4, 6, 'efg']])

    # check that a segment exactly at base is not trimmed.
    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(4, 'abcd')
    assert(asm.segments == [[4, 7, 'abcd']])

    # check that a segment exactly on the end is appended cleanly
    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(4, 'abcd')
    asm.add_segment(8, 'efgh')
    assert(asm.segments == [[4, 11, 'abcdefgh']])

    # check that a segment past the end is not coalesced
    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(4, 'abcd')
    asm.add_segment(9, 'efgh')
    assert(asm.segments == [[4, 7, 'abcd'], [9, 12, 'efgh']])

    # check that a segment inserted before the start is not coalesced
    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(9, 'efgh')
    asm.add_segment(4, 'abcd')
    assert(asm.segments == [[4, 7, 'abcd'], [9, 12, 'efgh']])

    # check one-byte segments
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    assert(asm.segments == [[1, 1, 'b']])

    asm.add_segment(3, 'd')
    assert(asm.segments == [[1, 1, 'b'], [3, 3, 'd']])

    asm.add_segment(5, 'f')
    assert(asm.segments == [[1, 1, 'b'], [3, 3, 'd'], [5, 5, 'f']])

    asm.add_segment(0, 'a')
    assert(asm.segments == [[0, 1, 'ab'], [3, 3, 'd'], [5, 5, 'f']])

    asm.add_segment(6, 'g')
    assert(asm.segments == [[0, 1, 'ab'], [3, 3, 'd'], [5, 6, 'fg']])

    asm.add_segment(7, 'h')
    assert(asm.segments == [[0, 1, 'ab'], [3, 3, 'd'], [5, 7, 'fgh']])

    asm.add_segment(4, 'e')
    assert(asm.segments == [[0, 1, 'ab'], [3, 7, 'defgh']])

    asm.add_segment(2, 'c')
    assert(asm.segments == [[0, 7, 'abcdefgh']])

    # check two-byte segments
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(4, 'ef')
    assert(asm.segments == [[4, 5, 'ef']])

    asm.add_segment(8, 'ij')
    assert(asm.segments == [[4, 5, 'ef'], [8, 9, 'ij']])

    asm.add_segment(12, 'mn')
    assert(asm.segments == [[4, 5, 'ef'], [8, 9, 'ij'], [12, 13, 'mn']])

    asm.add_segment(0, 'ab')
    assert(asm.segments == [
            [0, 1, 'ab'], [4, 5, 'ef'], [8, 9, 'ij'], [12, 13, 'mn']])

    asm.add_segment(14, 'op')
    assert(asm.segments == [
            [0, 1, 'ab'], [4, 5, 'ef'], [8, 9, 'ij'], [12, 15, 'mnop']])

    asm.add_segment(2, 'cd')
    assert(asm.segments == [
            [0, 5, 'abcdef'], [8, 9, 'ij'], [12, 15, 'mnop']])

    asm.add_segment(10, 'kl')
    assert(asm.segments == [[0, 5, 'abcdef'], [8, 15, 'ijklmnop']])

    asm.add_segment(6, 'gh')
    assert(asm.segments == [[0, 15, 'abcdefghijklmnop']])

    # check overlapping two-byte segments
    asm = Qe2Assembler()
    asm.base = 1
    asm.add_segment(4, 'ef')
    assert(asm.segments == [[4, 5, 'ef']])

    # after end
    asm.add_segment(5, 'Xg')
    assert(asm.segments == [[4, 6, 'efg']])

    # before start
    asm.add_segment(3, 'dX')
    assert(asm.segments == [[3, 6, 'defg']])

    # try adding again
    asm.add_segment(3, 'XX')
    assert(asm.segments == [[3, 6, 'defg']])

    asm.add_segment(10, 'kl')
    assert(asm.segments == [[3, 6, 'defg'], [10, 11, 'kl']])

    # add to start of hole
    asm.add_segment(6, 'Xh')
    assert(asm.segments == [[3, 7, 'defgh'], [10, 11, 'kl']])

    # add to end of hole
    asm.add_segment(9, 'jXX')
    assert(asm.segments == [[3, 7, 'defgh'], [9, 11, 'jkl']])

    # complete the hole
    asm.add_segment(7, 'XiX')
    assert(asm.segments == [[3, 11, 'defghijkl']])

    # fill variously sized holes
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    asm.add_segment(3, 'd')
    asm.add_segment(6, 'g')
    asm.add_segment(10, 'k')
    asm.add_segment(15, 'p')
    assert(asm.segments == [[1, 1, 'b'], [3, 3, 'd'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    # fill variously sized holes
    asm.add_segment(2, 'c')
    assert(asm.segments == [[1, 3, 'bcd'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(4, 'ef')
    assert(asm.segments == [[1, 6, 'bcdefg'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(7, 'hij')
    assert(asm.segments == [[1, 10, 'bcdefghijk'], [15, 15, 'p']])

    asm.add_segment(11, 'lmno')
    assert(asm.segments == [[1, 15, 'bcdefghijklmnop']])

    # Fill in with overlaps
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    asm.add_segment(3, 'd')
    asm.add_segment(6, 'g')
    asm.add_segment(10, 'k')
    asm.add_segment(15, 'p')
    assert(asm.segments == [[1, 1, 'b'], [3, 3, 'd'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(1, 'XcX')
    assert(asm.segments == [[1, 3, 'bcd'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(3, 'XefX')
    assert(asm.segments == [[1, 6, 'bcdefg'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(6, 'XhijX')
    assert(asm.segments == [[1, 10, 'bcdefghijk'], [15, 15, 'p']])

    asm.add_segment(10, 'XlmnoX')
    assert(asm.segments == [[1, 15, 'bcdefghijklmnop']])

    # Fill in with different overlaps
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    asm.add_segment(3, 'd')
    asm.add_segment(6, 'g')
    asm.add_segment(10, 'k')
    asm.add_segment(15, 'p')
    assert(asm.segments == [[1, 1, 'b'], [3, 3, 'd'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(0, 'aXcXe')
    assert(asm.segments == [[0, 4, 'abcde'], [6, 6, 'g'],
            [10, 10, 'k'], [15, 15, 'p']])

    asm.add_segment(5, 'fXhijXl')
    assert(asm.segments == [[0, 11, 'abcdefghijkl'], [15, 15, 'p']])

    asm.add_segment(13, 'noXqr')
    assert(asm.segments == [[0, 11, 'abcdefghijkl'], [13, 17, 'nopqr']])

    # check that segment prior

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'bcdefghijklmnopqrstuvwxyz')
    asm.add_segment(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCD')
    assert(asm.segments == [[0, 29, 'AbcdefghijklmnopqrstuvwxyzABCD']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    asm.add_segment(3, 'd')
    asm.add_segment(5, 'f')
    asm.add_segment(7, 'h')
    asm.add_segment(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCD')
    assert(asm.segments == [[0, 29, 'AbCdEfGhIJKLMNOPQRSTUVWXYZABCD']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(1, 'b')
    asm.add_segment(5, 'f')
    asm.add_segment(3, 'd')
    asm.add_segment(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    assert(asm.segments == [[0, 25, 'AbCdEfGHIJKLMNOPQRSTUVWXYZ']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(0, 'abcd')
    asm.add_segment(4, 'efgh')
    asm.add_segment(8, 'ijkl')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(8, 'ijkl')
    asm.add_segment(4, 'efgh')
    asm.add_segment(0, 'abcd')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(0, 'abcd')
    asm.add_segment(3, 'Xefgh')
    asm.add_segment(7, 'Xijkl')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(4, 'efgh')
    asm.add_segment(0, 'abcdX')
    asm.add_segment(7, 'Xijkl')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(4, 'efgh')
    asm.add_segment(0, 'abcdEFGHijkl')
    asm.add_segment(8, 'IJKL')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(4, 'e')
    asm.add_segment(6, 'g')
    asm.add_segment(0, 'abcdEfGhijkl')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(0, 'a')
    asm.add_segment(11, 'l')
    asm.add_segment(0, 'AbcdefghijkL')
    assert(asm.segments == [[0, 11, 'abcdefghijkl']])

    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(0, 'a')
    asm.add_segment(4, 'e')
    assert(asm.segments == [[4, 4, 'e']])

    asm = Qe2Assembler()
    asm.base = 4
    asm.add_segment(0, 'abcdef')
    assert(asm.segments == [[4, 5, 'ef']])

    asm = Qe2Assembler()
    asm.base = 1
    asm.add_segment(3, 'def')
    asm.add_segment(1, 'b')
    assert(asm.segments == [[1, 1, 'b'], [3, 5, 'def']])

    # adding prior to base
    asm = Qe2Assembler()
    asm.base = 2
    asm.add_segment(0, 'a')
    assert(asm.segments == [])
    asm.add_segment(1, 'b')
    assert(asm.segments == [])
    asm.add_segment(0, 'ab')
    assert(asm.segments == [])
    asm.add_segment(0, 'abc')
    assert(asm.segments == [[2, 2, 'c']])
    asm.add_segment(0, 'abXde')
    assert(asm.segments == [[2, 4, 'cde']])

    return 0

def test_covers():
    """
    Check segment_covers
    """

    x = Qe2Assembler.segment_covers([0, 4, 'abcde'], 1, 1)
    assert(x == [1, 1, 'b'])

    x = Qe2Assembler.segment_covers([0, 4, 'abcde'], 1, 2)
    assert(x == [1, 2, 'bc'])

    x = Qe2Assembler.segment_covers([0, 4, 'abcde'], 4, 4)
    assert(x == [4, 4, 'e'])

    x = Qe2Assembler.segment_covers([0, 4, 'abcde'], 3, 5)
    assert(x == [3, 4, 'de'])

    x = Qe2Assembler.segment_covers([0, 4, 'abcde'], 3, 5)
    assert(x == [3, 4, 'de'])

    return 0

def test_read():
    """
    test basic reading functionality
    """

    # default behavior, first segment not at base
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(3, 'def')
    assert(asm.segments == [[3, 5, 'def']])
    assert(asm.dequeue() == None)
    assert(asm.segments == [[3, 5, 'def']])

    # default behavior, first segment at base
    asm.add_segment(0, 'ab')
    assert(asm.segments == [[0, 1, 'ab'], [3, 5, 'def']])
    assert(asm.dequeue() == 'ab')
    assert(asm.segments == [[3, 5, 'def']])

    # partial dequeue, first segment not at base
    asm = Qe2Assembler()
    asm.base = 0
    asm.add_segment(3, 'def')
    assert(asm.dequeue(wanted_len=1) == None)
    assert(asm.segments == [[3, 5, 'def']])

    # partial dequeues, first segment at base
    asm.add_segment(0, 'ab')
    assert(asm.dequeue(wanted_len=1) == 'a')
    assert(asm.segments == [[1, 1, 'b'], [3, 5, 'def']])
    assert(asm.dequeue(wanted_len=1) == 'b')
    assert(asm.segments == [[3, 5, 'def']])

    # Now the first segment doesn't start at base, until we
    # fill in gap with a 'c'
    #
    assert(asm.dequeue(wanted_len=1) == None)
    assert(asm.segments == [[3, 5, 'def']])

    asm.add_segment(2, 'c')
    assert(asm.segments == [[2, 5, 'cdef']])
    assert(asm.dequeue(wanted_len=2) == 'cd')
    assert(asm.segments == [[4, 5, 'ef']])
    asm.add_segment(7, 'h')
    assert(asm.segments == [[4, 5, 'ef'], [7, 7, 'h']])
    assert(asm.dequeue(wanted_len=3) == 'ef')
    assert(asm.segments == [[7, 7, 'h']])
    # fill the hole
    asm.add_segment(6, 'g')
    # ask for more than there is
    assert(asm.dequeue(wanted_len=3) == 'gh')
    assert(asm.segments == [])
    assert(asm.base == 8)

    # Wanted == the length of the first and only segment
    asm = Qe2Assembler()
    asm.base = 3
    asm.add_segment(3, 'defgh')
    assert(asm.dequeue(wanted_len=5) == 'defgh')
    assert(asm.segments == [])
    assert(asm.base == 8)

    # Wanted == more the length of the first of two segments
    asm = Qe2Assembler()
    asm.base = 3
    asm.add_segment(3, 'def')
    asm.add_segment(7, 'hij')
    assert(asm.dequeue(wanted_len=5) == 'def')
    assert(asm.segments == [[7, 9, 'hij']])
    assert(asm.base == 6)

    return 0

def test_missing():

    asm = Qe2Assembler()
    asm.base = 2

    # Before we add any segments, missing is (asm.base, -1)
    assert(asm.first_missing() == (asm.base, -1))

    # Add a segment after the base (leaving a gap)
    asm.add_segment(4, '45')
    assert(asm.first_missing() == (2, 2))

    # Move base to the start of the segment, and first_missing becomes
    # the position after the end of the segment, with a length of -1
    asm.base = 4
    assert(asm.first_missing() == (6, -1))

    # Add a second segment to limit the length of the hole
    asm.add_segment(9, '9')
    assert(asm.first_missing() == (6, 3))
    # Fill in part of the hole, to make sure the size changes
    asm.add_segment(8, '8')
    assert(asm.first_missing() == (6, 2))
    asm.add_segment(7, '7')
    assert(asm.first_missing() == (6, 1))

    # And finish filling it in.
    asm.add_segment(6, '6')
    assert(asm.first_missing() == (10, -1))

    return 0

def test_main():
    """
    run the different tests
    """

    if test_covers():
        return 1
    if test_add():
        return 1
    if test_read():
        return 1

    if test_missing():
        return 1

    print 'SUCCESS'
    return 0

if __name__ == '__main__':
    sys.exit(test_main())

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
Simple unit test harnesses
"""

def test_encoder(encoder, decoder=None):
    """
    Takes an instance of HttpMoleEncoder (or equivalent),
    and does some test encodes and decodes and checks that
    the decode matches the encoded text and offset.

    Raises an AssertionError if any failures are detected.

    Returns 0 if no errors were detected.
    """

    if not decoder:
        decoder = encoder

    texts = ['', 'x', 'yy', 'zzz', 'fred is my name',
            'sdf' * 10, 'qwe' * 30, 'fredq3rF' * 100,
            chr(0) * 7, chr(1) * 37]
    offsets = [0, 1, 2, 3, 4, 5, 16, 21, 33, 44, 55]
    chaff_lens = [0, 1, 3, 4, 9, 12, 23, 32, 45]

    for text in texts:

        # Just to see something on the screen
        enc = encoder.encode(text, 10, 0)
        dec = decoder.decode(enc)
        print 'Encoded: [%s]' % enc
        print 'Decoded: [%s]' % str(dec)
        assert(text == dec[1])

        for offset in offsets:
            for chaff_len in chaff_lens:

                enc = encoder.encode(text, offset, chaff_len)
                dec = decoder.decode(enc)
                assert(offset == dec[0])
                assert(text == dec[1])

    return 0

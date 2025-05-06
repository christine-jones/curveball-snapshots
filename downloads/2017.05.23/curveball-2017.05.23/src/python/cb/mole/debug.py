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
Debugging/scaffolding versions of some of the helper classes.

These are only meant for diagnostic and testing purposes in
standalone tests; they don't satisfy all the requirements for
the classes they mimic.
"""

import binascii
import re

from cb.mole.encode import HttpMoleEncoder

class TestMoleEncoder(HttpMoleEncoder):
    """
    Simplified version of HttpMoleEncoder that only creates the "meat"
    of the encoding, and not a complete and valid GET request.

    This is intended only for debugging, and will eventually be removed.
    """

    MAX_UNENCODED_CHUNK_LEN = 16

    ENC_PATTERN = ( '^' + ('/([^/]*)' * 3) + '/')
    ERR_PATTERN = ENC_PATTERN

    def __init__(self, host):
        super(TestMoleEncoder, self).__init__(host)

    def encode(self, text, offset, chaff_length=0):
        """
        See cb.mole.encode.HttpMoleEncoder.encode()
        """

        # Leverage the error checking in HttpMoleEncoder,
        # and then throw away the result.

        super(TestMoleEncoder, self).encode(text, offset, chaff_length)

        if not text:
            text = ''

        text_len = len(text)

        # Ensure that there is at least one byte to encode.
        #
        if (text == '') and (chaff_length < 1):
            chaff_length = 1

        if chaff_length > 0:
            text += '0' * chaff_length

        hex_text = binascii.hexlify(text)

        request = '/%d/%d/%s/' % (offset, text_len, hex_text)

        return request


if __name__ == '__main__':
    import cb.mole.test

    def test_main():
        """
        Create a TestMoleEncoder and pass it it to cb.mole.test.test_encoder
        to see whether it behaves correctly.  Exits with status 0 if
        successful.
        """

        mole = TestMoleEncoder('foobar.org')
        retc = cb.mole.test.test_encoder(mole)

        if retc == 0:
            print "NO FAILURES / INCONCLUSIVE"
        return retc

    exit(test_main())

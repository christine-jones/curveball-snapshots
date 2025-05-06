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
Encoder/decoder for the mole format.

The initial format is simplistic and not cover.

TODO: add ticket describing need for better format.
"""

import binascii
import re

class HttpMoleEncoder(object):
    """
    A Mole encoder for HTTP.
    """

    # These are just random-looking strings to make it very unlikely that
    # the URLs we create will match any real resources on any site.
    #
    PATH_PREFIX = '3ks0.oe3'
    PATH_SUFFIX = 'hlA5.6th'

    # For now, we just encode a fixed size chunk, and don't make much of an
    # effort to maximize how much we can fit into each request (or minimize
    # overhead.
    #
    # TODO: write a ticket about this.
    #
    MAX_UNENCODED_CHUNK_LEN = 64

    URL_PATTERN = '/' + PATH_PREFIX + ('/([^/]*)' * 3) + '/' + PATH_SUFFIX
    ENC_PATTERN = '^GET ' + URL_PATTERN + ' HTTP/1.1\s*Host:\s([^\s]*)'

    ERR_PATTERN = URL_PATTERN

    def __init__(self, host):

        if type(host) != str:
            raise TypeError('host must be a str (not %s)' % str(type(host)))

        if not host:
            raise ValueError('host must not be the empty string')

        self.host = host
        self.offset = 0

    def encode(self, text, offset, chaff_length=0):
        """
        Offset is the length in the input stream, not the encoded stream

        Encode the given text, returning a mole encoding of the given text
        (plus optional chaff, of length chaff_length).

        If the text is '', then the chaff_len must be at least 1.
        The length of the text encoded (including the chaff) MUST
        be at least 1.

        IMPORTANT NOTE: The output of the encoder is never truncated; the
        entire text plus the requested amount of chaff are always encoded.
        If there are limits on how long the encoding can be (which the case
        for HTTP< where the encoding must fit within 2,000 bytes to work with
        most web servers), then it is responsibility of the CALLER to not
        request an encoding that will exceed that length.

        TODO: this is lame.  The encoder should not permit an encoding
        that is longer than the maximum permitted length (which should
        be intrinsic to each encoder class, possibly overridden in the
        constructor).  This method should consume as much as it can,
        and then return the rest.
        """

        # TODO: we should be able to handle other string-like types,
        # like buffers.  Right now we only do strings.
        #
        if type(text) != str:
            raise TypeError('text must be a str (not %s)' % str(type(text)))

        if type(offset) != int:
            raise TypeError('offset must be an int (not %s)' %
                    str(type(offset)))

        if type(chaff_length) != int:
            raise TypeError('chaff_length must be an int (not %s)' %
                    str(type(chaff_length)))

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

        request = 'GET /%s/%d/%d/%s/%s HTTP/1.1\r\nHost: %s\r\n\r\n' % (
                self.PATH_PREFIX,
                offset, text_len, hex_text,
                self.PATH_SUFFIX,
                self.host)

        return request

    def decode(self, encoded_text):
        """
        Given an encoded_text (such as created by encode), decode the
        text and return the original plaintext.

        The encoded_text parameter must contain at most one encoding.
        If it contains more than one (or parts of more than one) then
        this function will ignore all but the first complete encoding
        it finds.

        Returns (-1. '') if the decoding failed.
        """

        if type(encoded_text) != str:
            raise TypeError('encoded_text must be str (not %s)' %
                    str(type(encoded_text)))

        pattern = self.ERR_PATTERN

        match = re.search(pattern, encoded_text)
        if match:
            offset = int(match.group(1))
            length = int(match.group(2))
            hex_text = match.group(3)

            # assumes hex.
            # TODO: error checking!
            hex_text = hex_text[:2 * length]
            plain_text = binascii.unhexlify(hex_text)

            return (offset, plain_text)
        else:
            return (-1, '')

    def decode_response(self, response_text):
        """
        Given a server response from an encoded text, decode the text and
        return the original plaintext.

        For example, if the original text is "X", and the encoded text is
        "GET /X/..." then response might be a 404 page saying the URL X/...
        cannot be found, which can be decoded to extract the "X".

        The encoded_text parameter must contain at most one HTTP response.
        If it contains more than one (or parts of more than one) then
        this function will ignore all but the first complete encoding
        it finds embedded in a response.

        Returns (-1. '') if the decoding failed.
        """

        if type(response_text) != str:
            raise TypeError('response_text must be str (not %s)' %
                    str(type(response_text)))

        pattern = self.ERR_PATTERN

        match = re.search(pattern, response_text)
        if match:
            offset = int(match.group(1))
            length = int(match.group(2))
            hex_text = match.group(3)

            # assumes hex.
            # TODO: error checking!
            hex_text = hex_text[:2 * length]
            plain_text = binascii.unhexlify(hex_text)

            return (offset, plain_text)
        else:
            return (-1, '')


if __name__ == '__main__':
    import cb.mole.test

    def test_main():
        """
        Create a HttpMoleEncoder and pass it it to cb.mole.test.test_encoder
        to see whether it behaves correctly.  Exits with status 0 if
        successful.
        """

        mole = HttpMoleEncoder('foobar.org')
        retc = cb.mole.test.test_encoder(mole)

        if retc == 0:
            print "NO FAILURES / INCONCLUSIVE"
        return retc

    exit(test_main())


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
Encoder/decoder for the encrypted, somewhat obfuscated mole format.

NOTE that this encoder only works properly for channels that provide
in-order delivery.  The cipher use (RC4) is a stream cipher; it
maintains internal state that must be updated in the stream order.
"""

import binascii
import hashlib
import re
import sys

from M2Crypto import RC4

class HttpMoleCryptoEncoder(object):
    """
    A Mole encoder for HTTP that uses an encrypted, somewhat
    obfuscated format in order to make detection and eavesdropping
    somewhat more difficult.

    The format is described in general terms in the SDP.

    """

    # For now, we just encode a fixed size chunk, and don't make much of an
    # effort to maximize how much we can fit into each request (or minimize
    # overhead.
    #
    MAX_UNENCODED_CHUNK_LEN = 256

    # regexp of characters that can terminate a path.
    # FIXME: incomplete, probably.
    #PATHEXP = '([^\ <\n\r]*)'
    PATHEXP = '([^\ <\n\r\"\;\%\/\&\'\#\-]*)'

    HASHLEN = 8
    HASHSEP = ':'

    def __init__(self, host, session_key):

        if type(host) != str:
            raise TypeError('host must be a str (not %s)' % str(type(host)))

        if not host:
            raise ValueError('host must not be the empty string')

        self.host = host
        self.session_key = session_key
        self.offset = 0
        self.seqno = 0

        # TODO: check that the first 3000+ characters are thrown out.
        # The first part of an RC4 ciphertext are known to be weak.
        #
        self.rc4 = RC4.RC4(self.session_key)

        # Used to check that each instance is either used for encryption
        # or decryption, but never a mix
        #
        self.prev_crypto_op = None

        # print 'Created Encrypted Mole Encoder'

    def get_session_key(self):
        """
        Returns the session_key, which is currently the full_sentinel

        This function is primarily used by HTTP_CT_UNI_DP_NoHijack,
        which cannot easily obtain the sentinel otherwise
        """
        return self.session_key
    
    def reset_session_key(self):
        self.rc4 = RC4.RC4(self.session_key)        
        self.seqno = 0

    def encode(self, text, offset, chaff_length=0):
        """
        Offset is the length in the input stream, not the encoded stream

        The length of the text encoded (including the chaff) MUST
        be at least 1.

        The format is described in general terms in the SDP.
        The SDP should be updated with whatever we implement here.

        The steps for creating the URL for a given text at a given offset
        and a given amount of chaff are:

        1. Create the base URL path T:

            t = offset + "/" + textlen + "/" + hex(text) + hex(chaff)

        2. Compute a hash of T, and append it as a new component,
            creating URL path T':

            t2 = t + ":" + H(T)

            (We use a ":" as a separator to make it slightly simpler to
            tease t2 apart later)

        3. Encrypt t2, using some crypto function based on the session key,
            creating C.

            c = Encrypt(t2, self.session_key)

        4. Compute a prefix that encodes the request number, based on the
            session key, in order to give n an easily recognized prefix to
            search for during the decoding process:

            prefix = hex(H(('%.8x' % self.seq) + self.session_key))[0:HASHLEN]

            TODO: this is lame; we don't normalize the seqno prefix,
            but we really, really should.  FIXME

        5. Encode c in a form that can be represented by a URL path
            (using the correct alphabet, etc), to create n.  The normalization
            process may also insert forward slashes, or add suffixes or other
            obfuscating elements.

            n = Normalize(c)

        6. Return a complete GET request:

            "GET /" + prefix + n + " HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"

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

        text_t = '%d/%d/%s' % (text_len, offset, hex_text)

        text_t2 = self.add_digest(text_t)

        text_c = self.encrypt(text_t2)

        text_n = self.normalize(text_c)

        prefix = self.make_seqno_prefix()

        request = 'GET /%s HTTP/1.1\r\nHost: %s\r\n' % (
                prefix + text_n, self.host)

        request += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:33.0)  Gecko/20100101 Firefox/33.0\r\n"
        request += "Accept: text/html\r\n"
        request += "Accept-Language: en-US,en;q=0.5\r\n"
        request += "Accept-Encoding: \r\n"
        request += "Connection: keep-alive\r\n\r\n"

        return request

    def encrypt(self, plaintext):
        """
        Encrypt the given plaintext
        """

        # See comment in decrypt
        #
        if self.prev_crypto_op and self.prev_crypto_op != self.encrypt:
            raise RuntimeError('Same instance used for encrypt/decrypt')
        self.prev_crypto_op = self.encrypt

        return self.rc4.update(plaintext)

    def decrypt(self, ciphertext):
        """
        Decrypt the given ciphertext
        """

        # Note that the state of the cipher is updated by each operation,
        # and the offset into the stream is implicit, which means that
        # it is almost always an error to use the encrypt and decrypt
        # methods of the same instance, so we do a simple check to ensure
        # that this isn't the case.
        #
        if self.prev_crypto_op and self.prev_crypto_op != self.decrypt:
            raise RuntimeError('Same instance used for encrypt/decrypt')
        self.prev_crypto_op = self.decrypt

        return self.rc4.update(ciphertext)

    def add_digest(self, text):
        """
        Append simple message digest.

        See description of t2 in the comments for self.encode().
        """

        return '%s%s%s' % (text, self.HASHSEP, self.digest(text))

    def digest(self, message):
        """
        Append simple message digest, which takes the first 64 bits of md5.

        We aren't worried about the check being cryptographically strong
        (because this hash will itself be encrypted, so nobody can cause
        a useful collision without the key, which is strong)
        """

        hasher = hashlib.md5()
        hasher.update(message)
        digest = hasher.digest()[0:self.HASHLEN]

        return binascii.hexlify(digest)

    def verify(self, text):
        """
        Verify that the given text has the form specified for t2 in
        the description of the encode method.
        """

        components = text.split(self.HASHSEP)
        if len(components) != 2:
            print 'verify: cannot parse text [%s]' % text
            return False

        body, digest = components
        check = self.digest(body)

        if check == digest:
            return True
        else:
            print 'verify: Expected [%s] got [%s] text [%s]' % (
                    digest, check, text)
            return False

    def normalize(self, text):
        """
        Normalize the form of an encrypted string.

        TODO: obfuscate!  Right now all this does is hexlify.
        """

        return binascii.hexlify(text)

    def denormalize(self, text):
        """
        Must reverse self.normalize()
        """
        return binascii.unhexlify(text)

    def make_seqno_prefix(self, commit=True):
        """
        Return the identifying prefix, based on the sequence number
        and the session key.

        If it is not desired at this point to commit to incrementing
        the sequence number (e.g., because it is not yet known
        whether a decryption will succeed), set commit=False

        TODO: is self.HASHLEN the right length?  It's probably more
        than we need.  Just a few characters ought to do it.
        """

        prefix = self.digest(('%8x' % self.seqno) + self.session_key)
        prefix = prefix[0:self.HASHLEN]

        # In some cases, we don't want to increment the
        # sequence number until after we have correctly
        # decoded, so we pass a flag to not increment if
        # so desired.
        if commit == True:
            self.seqno += 1

        return prefix

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

        match = re.match('^GET /([^ ]*) HTTP/1.1', encoded_text)
        if not match:
            return (-1, '')

        encoded_path = match.group(1)

        return self.decode_path(encoded_path)

    def decode_path(self, encoded_path, expected_text_p=None, commit=True):
        """
        Given a path (with all the other text removed)
        decode the data encoded in that path.
        """
        text_p = encoded_path[:self.HASHLEN]
        text_n = encoded_path[self.HASHLEN:]

        if not expected_text_p:
            expected_text_p = self.make_seqno_prefix(commit)

        if expected_text_p != text_p:
            print 'Expected [%s]' % expected_text_p
            print 'Received [%s]' % text_p
            print 'ERROR: text_p does not match expected'
            return (-1, '')

        text_c = self.denormalize(text_n)

        text_t2 = self.decrypt(text_c)

        if not self.verify(text_t2):
            print 'text_t2 = [%s]' % text_t2
            print 'encoded_path = [%s]' % encoded_path
            print 'ERROR: verification failed'
            return (-1, '')

        # We correctly decoded, so now it is safe to increment
        # the sequence number
        #
        if commit == False:
            self.seqno += 1

        text_t = text_t2.split(self.HASHSEP)[0]

        # FIXME: this is done without any error checking.
        #
        text_len_str, offset_str, hex_text = text_t.split('/')
        text_len = int(text_len_str)
        offset = int(offset_str)
        text = binascii.unhexlify(hex_text)[0:text_len]

        return (offset, text)

    def decode_response(self, response_text, commit):
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

        If it is not desired at this point to commit to incrementing
        the sequence number (e.g., because it is not yet known
        whether a decryption will succeed), set commit=False
        """

        if type(response_text) != str:
            raise TypeError('response_text must be str (not %s)' %
                    str(type(response_text)))

        prefix = self.make_seqno_prefix(commit)
        # print >> sys.stderr, prefix
        # print >> sys.stderr, response_text

        # Search for the prefix, and try decoding whatever follows.
        # In the case of failure, try looking for the prefix later
        # in the response.
        #
        
        while True:
            candidate_start = response_text.find(prefix)

            if candidate_start < 0:
                #print 'no start [%s]' % response_text
                return (-1, '', '')

            response_text = response_text[candidate_start:]

            candidate_end = re.match(self.PATHEXP, response_text)
            if not candidate_end:
                print 'no end [%s]' % response_text
                return (-1, '', '')

            candidate = candidate_end.group(1)

            # print >> sys.stderr, 'res [%s]' % response_text
            # print >> sys.stderr, 'can [%s]' % candidate

            res = self.decode_path(candidate, prefix, commit)
            if res != (-1, ''):
                # print 'Decoded [%s]' % str(res)
                return res[0], res[1], candidate

            response_text = response_text[1:]

        print 'failed to find response'
        return (-1, '', '')


if __name__ == '__main__':
    import cb.mole.test

    def test_main():
        """
        Create encoder and decoder instances with the same hostname
        and key, and pass them to cb.mole.test.test_encoder to see
        whether they agree on a spectrum of data, offsets, and chaff.

        Exits with status 0 if successful.
        """

        encoder = HttpMoleCryptoEncoder('foobar.org', 'foobar')
        decoder = HttpMoleCryptoEncoder('foobar.org', 'foobar')
        retc = cb.mole.test.test_encoder(encoder, decoder=decoder)

        if retc == 0:
            print "NO FAILURES / INCONCLUSIVE"
        return retc

    exit(test_main())


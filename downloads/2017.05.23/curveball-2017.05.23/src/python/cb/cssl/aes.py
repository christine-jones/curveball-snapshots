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
Wrapper for simple crypto functions.

These will get more complicated when we're doing more complicated things, but
right now we're only doing AES256 in ECB mode.
"""

from M2Crypto import EVP

class CurveballAES256_ECB(object):
    """
    Simple implementation of an AES256 ECB encrypt/decrypt engine.

    Assumes that the input is properly padded (not just to a block boundary, but
    that the pad bytes are proper, etc).  DOES NOT ADD OR REMOVE PADDING.  DIES
    WHEN ASKED TO ENCRYPT BUFFERS THAT ARE NOT PADDED TO A BLOCK BOUNDARY.
    """

    def __init__(self, key):

        # Is this crucial?  Should we just pad it out if it's too short?
        #
        assert len(key) == 32

        self._key = key
        self._enc_cipher = None
        self._dec_cipher = None

        self._set_ciphers()

    def encrypt(self, plaintext):
        """
        Encrypt the given plaintext; return ciphertext.
        """

        return self._aes_ecb_worker(plaintext, mode='enc')

    def decrypt(self, ciphertext):
        """
        Decrypt the given ciphertext; return plaintext.
        """

        return self._aes_ecb_worker(ciphertext, mode='dec')

    def _set_ciphers(self):
        """
        Create the ciphers for encrypting and decrypting.

        It's not clear whether we need to have two ciphers or whether we could
        make do with one.  Better safe than sorry.
        """

        # This is fairly lame.  I'm not sure whether it matters.
        #
        enc_iv = '\0' * 32
        dec_iv = '\0' * 32

        self._enc_cipher = EVP.Cipher(alg='aes_256_ecb', key=self._key,
                iv=enc_iv, op=1, padding=0)
        
        self._dec_cipher = EVP.Cipher(alg='aes_256_ecb', key=self._key,
                iv=dec_iv, op=0, padding=0)
        
    def _aes_ecb_worker(self, text, mode):
        """
        Actually does the work of executing the cipher.

        After calling the final() method, the cipher needs to be reset; see
        comment below.
        """

        if mode == 'enc':
            cipher = self._enc_cipher
        elif mode == 'dec':
            cipher = self._dec_cipher
        else:
            # TODO: whoops!  We're going to crash in a moment.
            pass

        head = cipher.update(text)
        return head

class CurveballAES256_CBC(CurveballAES256_ECB):
    """
    Simple implementation of an AES256 CBC encrypt/decrypt engine.

    Assumes that the input is properly padded (not just to a block boundary, but
    that the pad bytes are proper, etc).  DOES NOT ADD OR REMOVE PADDING.  DIES
    WHEN ASKED TO ENCRYPT BUFFERS THAT ARE NOT PADDED TO A BLOCK BOUNDARY.
    """

    def __init__(self, key, iv):
        self.iv = iv
        CurveballAES256_ECB.__init__(self, key)


    def _set_ciphers(self):
        """
        Create the ciphers for encrypting and decrypting.

        It's not clear whether we need to have two ciphers or whether we could
        make do with one.  Better safe than sorry.
        """


        self._enc_cipher = EVP.Cipher(alg='aes_256_cbc', key=self._key,
                iv=self.iv, op=1, padding=0)
        
        self._dec_cipher = EVP.Cipher(alg='aes_256_cbc', key=self._key,
                iv=self.iv, op=0, padding=0)
        

class CurveballAES256_ECB_padded(CurveballAES256_ECB):
    """
    Simple implementation of an AES256 ECB encrypt/decrypt engine.

    Adds/removes padding during encrypt/decrypt.
    """

    def __init__(self, key):
        CurveballAES256_ECB.__init__(self, key)

    def _set_ciphers(self):
        """
        Create the ciphers for encrypting and decrypting.

        It's not clear whether we need to have two ciphers or whether we could
        make do with one.  Better safe than sorry.
        """

        CurveballAES256_ECB._set_ciphers(self)

        self._enc_cipher.set_padding(padding=1)
        self._dec_cipher.set_padding(padding=1)

    def _aes_ecb_worker(self, text, mode):
        """
        Actually does the work of executing the cipher.

        After calling the final() method, the cipher needs to be reset; see
        comment below.
        """

        if mode == 'enc':
            cipher = self._enc_cipher
        elif mode == 'dec':
            cipher = self._dec_cipher
        else:
            # TODO: whoops!  We're going to crash in a moment.
            pass

        head = cipher.update(text)
        tail = cipher.final()

        # TODO: figure out a better way to clean this up.  Every time we
        # call cipher.final(), the state of the cipher gets clobbered and we
        # shouldn't use it afterward, so we need to reset it.  Right now we
        # just reset everything.  This will break in CBC.
        #
        self._set_ciphers()

        return head + tail


class CurveballAES256_CBC_padded(CurveballAES256_ECB_padded):
    """
    Simple implementation of an AES256 CBC encrypt/decrypt engine.
    """

    def __init__(self, key):
        CurveballAES256_ECB_padded.__init__(self, key)

    def _set_ciphers(self):
        """
        Create the ciphers for encrypting and decrypting.

        It's not clear whether we need to have two ciphers or whether we could
        make do with one.  Better safe than sorry.
        """

        # This is fairly lame.  I'm not sure whether it matters.
        #
        enc_iv = '\0' * 32
        dec_iv = '\0' * 32

        self._enc_cipher = EVP.Cipher(alg='aes_256_cbc', key=self._key,
                iv=enc_iv, op=1, padding=1)
        
        self._dec_cipher = EVP.Cipher(alg='aes_256_cbc', key=self._key,
                iv=dec_iv, op=0, padding=1)



if __name__ == '__main__':

    def test_unpadded(cipher, blksz):
        "test for ciphers that don't pad."

        ptexts = [
                'a' * blksz,
                'bc' * blksz,
                'def' * blksz,
                'ghij' * blksz,
                'klmno' * blksz,
                'f' * 999 * blksz,
                'g' * 2001 * blksz,
                ]
        ctexts = []
        dtexts = []
        attempts = 0
        successes = 0

        for text in ptexts:
            ctext = cipher.encrypt(text)
            ctexts.append(ctext)

            if len(ctext) != len(text):
                print 'odd: wrong block size?'

        for text in ctexts:
            dtext = cipher.decrypt(text)
            dtexts.append(dtext)

        for index in range(0, len(ptexts)):
            attempts += 1
            if ptexts[index] != dtexts[index]:
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            elif len(ptexts[index]) != len(dtexts[index]):
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            else:
                successes += 1

        return (attempts, successes)

    def test_padded(cipher):
        """
        test for ciphers that do their own padding
        """

        ptexts = [
                'short',
                'this is sixteen.',
                'here is something',
                'here is something a little longer',
                'here is something in the middle',
                'here is exactly len thirty---two',
                'here is something random',
                'here is something long enough to span two blocks',
                'here is something that should be long enough to span' +
                    ' into a third block, if my calculations are correct'
                ]
        ctexts = []
        dtexts = []
        attempts = 0
        successes = 0

        for text in ptexts:
            ctext = cipher.encrypt(text)
            ctexts.append(ctext)

        for text in ctexts:
            dtext = cipher.decrypt(text)
            dtexts.append(dtext)

        for index in range(0, len(ptexts)):
            attempts += 1
            if ptexts[index] != dtexts[index]:
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            elif len(ptexts[index]) != len(dtexts[index]):
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            else:
                successes += 1

        return (attempts, successes)


    def main():
        """ test main """

        key = '1' * 32

        attempts = 0
        successes = 0

        cipher = CurveballAES256_ECB(key)
        (n_attempts, n_successes) = test_unpadded(cipher, 16)
        attempts += n_attempts
        successes += n_successes

        cipher = CurveballAES256_CBC(key)
        (n_attempts, n_successes) = test_unpadded(cipher, 16)
        attempts += n_attempts
        successes += n_successes

        cipher = CurveballAES256_ECB_padded(key)
        (n_attempts, n_successes) = test_padded(cipher)
        attempts += n_attempts
        successes += n_successes

        cipher = CurveballAES256_CBC_padded(key)
        (n_attempts, n_successes) = test_padded(cipher)
        attempts += n_attempts
        successes += n_successes

        if (attempts > 0) and (attempts == successes):
            print 'SUCCESS %d attempts' % (attempts,)
            return 0
        else:
            print 'success %d attempts %d' % (successes, attempts)
            return 1

    exit(main())



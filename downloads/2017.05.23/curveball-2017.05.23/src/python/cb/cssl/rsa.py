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
"""

import binascii
import hashlib

from M2Crypto import EVP
from M2Crypto import BIO
from M2Crypto import RSA

class CurveballRSA(object):
    """
    Simple wrapper for the icky OpenSSL RSA encrypt/decrypt engine.
    """

    def __init__(self, public_key_fname, private_key_fname, passphrase=''):

        self._pri = None
        self._pri_str = None

        self._pub = None
        self._pub_str = None

        self._passphrase = passphrase

        self._pad_type = RSA.pkcs1_padding

        self.set_pubkey(public_key_fname)
        self.set_prikey(private_key_fname, passphrase)

    def set_pubkey(self, public_key_fname):
        """
        Set the public key
        """

        if public_key_fname:
            # TODO: try block around file ops
            key_str = open(public_key_fname).read()
            bio = BIO.MemoryBuffer(key_str)
            key = RSA.load_pub_key_bio(bio)
        else:
            key_str = None
            key = None

        self._pub = key
        self._pub_str = key_str

    def set_prikey(self, private_key_fname, passphrase=None):
        """
        Set the private key
        """

        if private_key_fname:
            # TODO: try block around file ops
            key_str = open(private_key_fname).read()
            if passphrase:
                key = RSA.load_key_string(key_str,
                        lambda *args: passphrase)
            else:
                key = RSA.load_key_string(key_str, lambda *args: 1)
        else:
            key_str = None
            key = None

        self._pri = key
        self._pri_str = key_str
        self._passphrase = passphrase

    def encrypt(self, plaintext):
        """
        Encrypt using public key.
        """

        # TODO: is this the correct kind of padding?
        #
        return self._pub.public_encrypt(plaintext, self._pad_type)

    def decrypt(self, ciphertext):
        """
        Decrypt using private key.
        """

        # TODO: is this the correct kind of padding?
        #
        return self._pri.private_decrypt(ciphertext, self._pad_type)

    def old_sign(self, text):
        """
        Sign using private key.
        """

        key = EVP.load_key_string(self._pri_str,
                lambda *args: self._passphrase)

        key.reset_context(md='sha1')
        key.sign_init()
        key.sign_update(text)
        signature = key.sign_final()

        (odig, osig) = self.sign2(text)

        return signature

    def sign(self, text):
        """
        Create sha1 digest, and then sign it
        """

        sha1 = hashlib.sha1()
        sha1.update(text)
        digest = sha1.digest()

        #debug
        signature = self._pri.sign(digest)

        return signature

    def verify(self, signed_text, signature):
        """
        Verify the signature, using the public key.
        """

        key = EVP.PKey()

        # capture=False means "Don't destroy the key.  I might want it for
        # something else so don't free it."
        #
        key.assign_rsa(self._pub, capture=False)
        key.reset_context(md='sha1')
        key.verify_init()
        key.verify_update(signed_text)

        return key.verify_final(signature)

    def verify2(self, signed_text, signature):
        """
        This should work, but doesn't.
        I'm doing something wrong.
        """

        return self._pub.verify(signed_text, signature, algo='sha1')



if __name__ == '__main__':

    def main():
        """ test main """

        # If you want to create new RSA pub/priv key pairs, and store
        # them in rsa-test.*.pem, here's a snippet of code to create a
        # key with a password of 'rsa-testpw':
        #
        # rsaKey = M2Crypto.RSA.gen_key(1024, 65537)
        #     return 'rsa-testpw'
        #
        # def pw_callback(*args, **kwds):
        #     return 'rsa-testpw'
        #
        # rsaKey.save_key('rsa-test.priv.pem', callback=pw_callback)
        # rsaKey.save_pub_key('rsa-test.pub.pem')

        key = '1' * 32
        rsa = CurveballRSA('rsa-test.pub.pem',
                'rsa-test.priv.pem', passphrase='rsa-testpw')

        ptexts = [
                'short',
                'this is sixteen.',
                'here is something',
                'here is something a little longer',
                'here is something in the middle',
                'here is exactly len thirty---two',
                'here is something random',
                'here is something just a week bit longer'
                ]
        ctexts = []
        dtexts = []

        for text in ptexts:
            ctext = rsa.encrypt(text)
            ctexts.append(ctext)

        for text in ctexts:
            dtext = rsa.decrypt(text)
            dtexts.append(dtext)

        attempts = 0
        successes = 0
        for index in range(0, len(ptexts)):
            attempts += 1
            if ptexts[index] != dtexts[index]:
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            elif len(ptexts[index]) != len(dtexts[index]):
                print 'whoops! %s != %s' % (ptexts[index], dtexts[index])
            else:
                successes += 1


        ctexts = []
        dtexts = []
        for text in ptexts:
            ctext = (text, rsa.sign(text))
            ctexts.append(ctext)

        for (text, signature) in ctexts:
            attempts += 1
            if rsa.verify(text, signature):
                successes += 1

        for (text, signature) in ctexts:
            attempts += 2

            # this should fail because we've changed the text.
            if not rsa.verify('a' + text, signature):
                successes += 1

            # this should fail because we've changed the text.
            new_text = text.upper()
            if not rsa.verify(new_text, signature):
                successes += 1

        if (attempts > 0) and (attempts == successes):
            return 0
        else:
            return 1

    exit(main())



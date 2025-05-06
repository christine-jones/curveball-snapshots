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

import random
import string
import base64
import binascii
import hashlib
import string
import zlib
import os
import sys
import exceptions

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cb_constants as const
import cb.util.cb_constants_dp as const_dp
from M2Crypto import RSA, BIO, EVP


# The directory that this executable lives in.
#
DIRNAME = os.path.normpath(
            os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))

#sys.path.append(os.path.normpath(os.path.join(DIRNAME, '..', '../../build/auth/certs')))

def get_privkey_file(self):
    """
    Locate file containing private key

    """

    #privkeys = ['../auth/certs/priv.pem',
    #            '../../build/auth/certs/priv.pem'
    #            ]

    privkey_fname = os.path.join(DIRNAME,
            const_dp.RELATIVE_PATH_BUILD_PRIV_KEY,
            const_dp.DP_PRIV_KEY_NAME)

    if os.path.exists(privkey_fname):
        return privkey_fname

    privkey_fname = os.path.join(DIRNAME, const_dp.RELATIVE_PATH_PRIV_KEY,
            const_dp.DP_PRIV_KEY_NAME)

    if os.path.exists(privkey_fname):
        return privkey_fname

    raise exceptions.IOError("Can't find private keyfile")

def obtain_privkey_dp(self):
    """
    Locate and load private key from file

    """

    privkey_fname = get_privkey_file(self)

    f = open(privkey_fname)
    privkey_dp = f.read()

    return privkey_dp


def privkey_decrypt(self, enc_text):
    """
    Decrypt enc_text using private key

    """

    privkey_fname = get_privkey_file(self)
    privkey_dp = RSA.load_key(privkey_fname)
    try:
        text = privkey_dp.private_decrypt( enc_text, RSA.pkcs1_oaep_padding )
    except:
        print "Error: text cannot be decrypted"

    return text


def signature_privkey_dp(self, text):
    """
    Sign text using private key

    """
    privkey_fname = get_privkey_file(self)

    sig = EVP.load_key(privkey_fname)
    sig.sign_init()
    sig.sign_update( text )
    signature = sig.sign_final()
    return signature


if __name__ == '__main__':
    pass








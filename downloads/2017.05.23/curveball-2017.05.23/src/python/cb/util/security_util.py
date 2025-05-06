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

import base64
import binascii
import exceptions
import hashlib
import os
import random
import string
import sys
import zlib

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cb_constants as const
from M2Crypto import RSA, BIO, EVP


# The directory that this executable lives in.
#
DIRNAME = os.path.normpath(
            os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))


def encrypt_text(self, clear_text, key, is_hex, is_zip, is_base64):
    """
    Encrypt the clear_text using the passed key

    After encryption, text may additionally be hexilified, zipped,
    and/or converted to base64
    """

    clear_text = str(len(clear_text)) + ' ' + clear_text
    text_len = len(clear_text)
    enc = ''

    for i in range(0, text_len, const.ENCRYPTION_BLOCK_LEN):

        block_end = i + const.ENCRYPTION_BLOCK_LEN
        if block_end <= text_len:

            enc_block = key.encrypt(clear_text[i:block_end])

        else:
            padding_len = block_end - text_len
            padding_bits = ''.join(
                    random.choice(string.ascii_uppercase + string.digits)
                            for x in range(padding_len))

            clear_block = clear_text[i:] + padding_bits
            enc_block = key.encrypt(clear_block)

        enc = enc + enc_block

    if is_hex == True:
        enc = binascii.hexlify(enc)

    if is_zip == True:
        enc = zlib.compress(enc)

    if is_base64 == True:
        enc = base64.b64encode(enc)

    return enc

def decrypt_text(self, enc, key, is_hex, is_zip, is_base64):
    """
    Decrypt the encrypted text, enc, using the passed key

    Before decryption, text may additionally be unhexilified, unzipped,
    and/or converted from base64
    """

    if is_base64 == True:
        try:
            enc = base64.b64decode(enc)
        except TypeError, _exc:
            print 'Error: bad Base64 characters found'
            return -1

    if is_zip == True:
        try:
            enc = zlib.decompress(enc)
        except zlib.error:
            print 'Error: not zlib compressed'
            return -1

    if is_hex == True:
        try:
            enc = binascii.unhexlify(enc)
        except TypeError, _exc:
            print 'Error: bad hex found'
            return -1

    text_len = len(enc)
    dec = ''

    for i in range(0, text_len, const.ENCRYPTION_BLOCK_LEN):

        block_end = i + const.ENCRYPTION_BLOCK_LEN
        if block_end <= text_len:
            try:
                decrypted_block = key.decrypt (enc[i:block_end])
            except BaseException, exc:
                print 'Error: could not decrypt [%s]' % str(exc)
                return -1
        else:
            decrypted_block = ''
            print 'Error: incorrect padding'
            return -1
        dec = dec + decrypted_block

    try:
        i = dec.index(' ')
        str_len = dec[0:i]
        dec = dec[i + 1 : i + int(str_len) + 1]

    except ValueError, exc:
        print 'Error: bad encoded string length [%s]' % str(exc)
        return -1

    return dec

def compute_keys(self, premaster, nonce_client, nonce_dp):
    """
    Computing keys following TLS RFC
    """

    key_block = compute_key_block(self, premaster, nonce_client, nonce_dp)

    mac1 = const.MAC_HEX_LEN
    mac2 = mac1 + const.MAC_HEX_LEN
    key1 = mac2 + const.TEMP_KEY_HEX_LEN
    key2 = key1 + const.TEMP_KEY_HEX_LEN
    iv1 = key2 + const.IV_HEX_LEN
    iv2 = iv1 + const.IV_HEX_LEN

    mac_c = key_block[0    : mac1]
    mac_d = key_block[mac1 : mac2]
    key_c = key_block[mac2 : key1]
    key_d = key_block[key1 : key2]
    iv_c  = key_block[key2 : iv1]
    iv_d  = key_block[iv1  : iv2]


    client_hash = hashlib.sha256(
            key_c + nonce_client + nonce_dp).hexdigest()[0:const.KEY_HEX_LEN]
    dp_hash = hashlib.sha256(
            key_d + nonce_dp + nonce_client).hexdigest()[0:const.KEY_HEX_LEN]

    client_key = cb.cssl.aes.CurveballAES256_CBC(client_hash, iv_c)
    dp_key = cb.cssl.aes.CurveballAES256_CBC(dp_hash, iv_d)

    return [client_key, dp_key, client_hash, dp_hash]

def compute_key_block(self, premaster, n_client, n_dp):
    """
    Computing key block following TLS RFC

    key_block is in hex digits
    """

    a = hashlib.sha256('A' + premaster + n_client + n_dp).hexdigest()
    b = hashlib.sha256('BB' + premaster + n_client + n_dp).hexdigest()
    c = hashlib.sha256('CCC' + premaster + n_client + n_dp).hexdigest()
    aa = hashlib.sha256(premaster + a).hexdigest()
    bb = hashlib.sha256(premaster + b).hexdigest()
    cc = hashlib.sha256(premaster + c).hexdigest()
    master_secret = aa + bb + cc

    a = hashlib.sha256('A' + master_secret + n_client + n_dp).hexdigest()
    b = hashlib.sha256('BB' + master_secret + n_client + n_dp).hexdigest()
    c = hashlib.sha256('CCC' + master_secret + n_client + n_dp).hexdigest()
    aa = hashlib.sha256(master_secret + a).hexdigest()
    bb = hashlib.sha256(master_secret + b).hexdigest()
    cc = hashlib.sha256(master_secret + c).hexdigest()
    key_block = aa + bb + cc

    return key_block

def obtain_extra_keys(self, sentinel_hex):
    """
    Create keys from sentinel label (extra bits)
    """

    key_x = sentinel_hex[const.KEY_HEX_LEN:]
    iv_x = sentinel_hex[:const.KEY_HEX_LEN]

    extra_d2c_key = cb.cssl.aes.CurveballAES256_CBC(key_x, iv_x)

    return [extra_d2c_key]

def get_pubkey_file(self):
    """
    Locate file containing public key
    """

    pubkey_fname = os.path.join(DIRNAME, const.RELATIVE_PATH_BUILD_PUB_KEY,
            const.DP_PUB_KEY_NAME)

    if os.path.exists(pubkey_fname):
        return pubkey_fname

    pubkey_fname = os.path.join(DIRNAME, const.RELATIVE_PATH_PUB_KEY,
            const.DP_PUB_KEY_NAME)

    if os.path.exists(pubkey_fname):
        return pubkey_fname

    pubkey_fname = os.path.join(DIRNAME, const.RELATIVE_PATH_WIN_PUB_KEY,
            const.DP_PUB_KEY_NAME)

    if os.path.exists(pubkey_fname):
        return pubkey_fname

    raise exceptions.IOError("Can't find public keyfile %s" %
            const.DP_PUB_KEY_NAME)

def obtain_pubkey_dp(self):
    """
    Locate and load file containing public key
    """

    pubkey_fname = get_pubkey_file(self)

    f = open(pubkey_fname)
    pubkey_dp = f.read()

    return pubkey_dp

def verify_signature(self, pubkey, str_to_verify, signature):
   """
   Verify that signature matches str_to_verify
   """

   k = RSA.load_pub_key_bio(BIO.MemoryBuffer(pubkey))
   ver = EVP.PKey()
   ver.assign_rsa(k)
   ver.verify_init()
   ver.verify_update(str_to_verify)

   if ver.verify_final(signature) == False:
       print 'Error: message is not as expected, may be adversary'
       return False
   else:
       return True

if __name__ == '__main__':
    pass


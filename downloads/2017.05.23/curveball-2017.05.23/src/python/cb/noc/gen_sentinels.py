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

# Generate test sentinels to std_out
# input: keyfile, # of sentinels / key
# output: sentinel to std_out

# ~3m10s to create 6.4M sentinels

# todo:
# add exception handling and usage block

# keyfile is assumed to be formatted as: 'index key'

"""
Routines to help generate sentinel strings
"""

import datetime
import hashlib
import hmac
import sys

# The parameters of the group used for the MSE Diffie-Hellman exchange
#
# MSE_DH_GROUP_HEX is the prime used to create the Diffie-Hellman group,
# expressed in hex.
#
# MSE_DH_GROUP is the integer representation of this prime.
#
# MSE_DH_GENERATOR is the generator used by the MSE Diffie-Hellman exchange.
#
# These constants are taken directly from the BitTorrent MSE spec.
#
MSE_DH_GROUP_HEX = '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563'
MSE_DH_GROUP = int(MSE_DH_GROUP_HEX, 16)
MSE_DH_GENERATOR = 2

# The length of the "sentinel prefix"; the part of the sentinel that
# is searched for by the DR.  This is currently 8 bytes.
#
# The sentinel is the concatenation of the sentinel prefix and the
# sentinel label, but in many parts of the code "sentinel prefix"
# and "sentinel" are treated as synonyms.
#
SENTINEL_PREFIX_LEN = 8
SENTINEL_PREFIX_HEX_LEN = 2 * SENTINEL_PREFIX_LEN

# Set to True if sentinels last a day, False if they need to change on
# the hour.  CB_PER_DAY_SENTINELS makes it easier to debug and test,
# since we don't have to update sentinel files every hour.
CB_PER_DAY_SENTINELS=False

def create_date_hmac_str(utc=None):
    """
    Create the 'time-based seed' for the sentinel generator HMAC,
    based on the given datetime.datetime UTC instance.

    If utc is None, then the current UTC is used.
    """

    if utc == None:
        utc = datetime.datetime.utcnow()

    if CB_PER_DAY_SENTINELS:
        return utc.strftime('%Y-%m-%d')
    else:
        return utc.strftime('%Y-%m-%d %H')

def create_sentinel(mykey, number, time_str=None):
    """
    Given a key, number, and optional time_str, create the corresponding
    sentinel.

    If time_str is not supplied, then it is computed directly by calling
    create_date_hmac_str.
    """

    if time_str == None:
        time_str = create_date_hmac_str()
    msg = '%s %d' % (time_str, number)
    return hmac.new(mykey, msg, hashlib.sha256).hexdigest() # removed [:16], now returns entire hash

def create_mse_sentinel(mykey, number, time_str=None):
    """
    Given a key, number, and optional time_str, create the corresponding
    sentinel for use with the Curveball MSE handshake.

    If time_str is not supplied, then it is computed directly by calling
    create_date_hmac_str.

    Unlike create_sentinel, this returns a pair (sentinel, exp), where
    sentinel is the full sentinel (the eight-binary-byte, or
    sixteen-byte-hex prefix followed by the sentinel label) and exp
    is the 768-bit exponent of the generator that corresponds to the
    sentinel.
    """

    if time_str == None:
        time_str = create_date_hmac_str()

    # Create the sentinel label portion first; it's identical to
    # the sentinel label created by create_sentinel.  Since this
    # is hex, we slice off the first SENTINEL_PREFIX_HEX_LEN bytes
    # and keep the rest.
    #
    scratch = create_sentinel(mykey, number, time_str=time_str)
    sentinel_label = scratch[SENTINEL_PREFIX_HEX_LEN:]

    hash0_msg = '%s %d BitTorrent1' % (time_str, number)
    hash1_msg = 'BitTorrent2 %d %s' % (number, time_str)

    hash0 = hmac.new(mykey, hash0_msg, hashlib.sha512).hexdigest()
    hash1 = hmac.new(mykey, hash1_msg, hashlib.sha256).hexdigest()

    hex_exp = hash0 + hash1

    exp = int(hex_exp, 16)

    g_exp = pow(2, exp, MSE_DH_GROUP)

    g_exp_hex = '%x' % g_exp

    sentinel = g_exp_hex[:SENTINEL_PREFIX_HEX_LEN]

    sentinel += sentinel_label

    return (sentinel, hex_exp, g_exp_hex)

def gen_sentinels(key_file, num_sentinels, utc=None):

    if not utc:
        utc = datetime.datetime.utcnow()

    time_str = create_date_hmac_str(utc)
    retval = []

    # Here we have hex versions of the sentinels
    # the actual sentinels are made using
    # binascii.unhexlify(sentinel[:SENTINEL_PREFIX_HEX_LEN])
    # to get binary versions of the sentinel prefix.
    # the remainder (sentinel[SENTINEL_PREFIX_HEX_LEN:]) is the
    # "extra bits" or "sentinel label"

    for line in open(key_file, 'r'):
        key = line.split()
        for i in range (0, num_sentinels):
            sentinel = create_sentinel(key[1], i, time_str)
            # it's not clear we need to return i, here --- the program
            # originally printed the index for the sentinels generated
            # for each key, and the C program still does, but
            # otherwise i isn't needed
            # (bear in mind that i goes from 0..num_sentinels for each
            # key in the key-file)
            retval.append([i, sentinel[:SENTINEL_PREFIX_HEX_LEN],
                    sentinel[SENTINEL_PREFIX_HEX_LEN:]])

    return retval

def gen_mse_sentinels(key_file, num_sentinels, utc=None):
    """
    Like gen_sentinels, but returns a list of 4-tuples
    (i, sentinel, sentinel_label, dh_secret)
    """

    if not utc:
        utc = datetime.datetime.utcnow()

    time_str = create_date_hmac_str(utc)
    retval = []

    # Here we have hex versions of the sentinels
    # the actual sentinels are made using
    # binascii.unhexlify(sentinel[:SENTINEL_PREFIX_HEX_LEN])
    # to get binary versions of the sentinel prefix.
    # the remainder (sentinel[SENTINEL_PREFIX_HEX_LEN:]) is the
    # "extra bits" or "sentinel label"

    for line in open(key_file, 'r'):
        key = line.split()
        for i in range (0, num_sentinels):
            (sentinel, dh_key, _dh_pub) = create_mse_sentinel(
                    key[1], i, time_str)
            # it's not clear we need to return i, here --- the program
            # originally printed the index for the sentinels generated
            # for each key, and the C program still does, but
            # otherwise i isn't needed
            # (bear in mind that i goes from 0..num_sentinels for each
            # key in the key-file)
            retval.append([i, sentinel[:SENTINEL_PREFIX_HEX_LEN],
                    sentinel[SENTINEL_PREFIX_HEX_LEN:], dh_key])

    return retval

if __name__ == '__main__':

    if len(sys.argv) > 2:
        key_file = sys.argv[1]
        num_sentinels = int(sys.argv[2])
    else:
        print "Usage: %s key-file num-sentinels" % sys.argv[0]
        sys.exit(1)

    sents = gen_sentinels(key_file, num_sentinels)

    for item in sents:
        print "%d %s %s" % (item[0], item[1], item[2])

    print 'generating MSE sentinels'
    sents = gen_mse_sentinels(key_file, num_sentinels)

    # make a histogram of the first hex digit of each sentinel
    # to verify that they're spread out uniformly
    #
    hist = dict()
    for item in sents:
        print "%d %s %s %s" % (item[0], item[1], item[2], item[3])

        pref = item[3][0]
        if not pref in hist.keys():
            hist[pref] = 1
        else:
            hist[pref] += 1

    print hist


#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017 and in
# part by a grant from the United States Department of State.
# The opinions, findings, and conclusions stated herein are those
# of the authors and do not necessarily reflect those of the United
# States Department of State.
#
# Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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
Routines and a utility to help generate sentinel strings

key_file is assumed to be formatted as: 'kname key'
"""

import binascii
import datetime
import os

import cb.noc.file
import cb.noc.gen_sentinels as gen_sentinels

from cbbloom import CB_BloomFilter

def sentinel_file_name(utc, out_dir):
    sent_fname = cb.noc.file.sentinel_fname(utc)

    return os.path.join(out_dir, sent_fname)

def dhexp_file_name(utc, out_dir):
    """
    Return the name of the sentinel<-->Diffie-Hellman exponent 
    map for the given utc, in the given out_dir
    """

    fname = cb.noc.file.dhexp_fname(utc)

    return os.path.join(out_dir, fname)
        
def make_sentbf_file(utc, out_dir, nhours=1, curr_sbf_fname=None,
        safe=False):
    """
    Create the Bloom filter file for the sentinels in the
    current and previous hours, and place it in out_dir.

    The sentinel files for the current and previous hours are
    assumed to already exist (in out_dir).
    """

    # Construct output filename, and then construct the file itself.
    #

    # Find the input file names.
    #
    # We construct Bloom filters that contain the current hour (for utc)
    # and the previous hour.
    #
    delta = datetime.timedelta(hours=1)

    prev_sent_fname = cb.noc.file.sentinel_fname(utc - delta)
    prev_sents = open(os.path.join(out_dir, prev_sent_fname), 'r').readlines()

    curr_sents = list()
    for hour in range(0, nhours):
        curr_sent_fname = cb.noc.file.sentinel_fname(utc + (delta * hour))

        fin = open(os.path.join(out_dir, curr_sent_fname), 'r')
        curr_sents += fin.readlines()
        fin.close()

    num_entries = 2 * (len(curr_sents) + len(prev_sents))
    sbf = CB_BloomFilter(capacity=num_entries)

    if not curr_sbf_fname:
        curr_sbf_fname = cb.noc.file.sentinel_bf_name(utc)
    else:
        # The combo file doesn't have a generation number
        #
        # 2013/09/03 - The combo file was used at one point
        # for debugging; it might be dead code at this point
        #
        curr_sbf_fname = 'combo-%d-%s' % (nhours,
                cb.noc.file.sentinel_bf_name(utc))

    curr_sbf_path = os.path.join(out_dir, curr_sbf_fname)

    if safe and os.path.isfile(curr_sbf_path):
        print "Skipping (%s)" % (curr_sbf_path,)
        return
    else:
        print "Creating (%s)" % (curr_sbf_path,) # debugging

    # Load sentinels into the Bloom filter, trimming the sentinels to
    # 64 bits for https and
    # 128 bits for http
    #
    for sent in prev_sents:
        sbf.add(binascii.unhexlify(sent.rstrip()[0:16]))
        sbf.add(binascii.unhexlify(sent.rstrip()[0:32]))

    for sent in curr_sents:
        sbf.add(binascii.unhexlify(sent.rstrip()[0:16]))
        sbf.add(binascii.unhexlify(sent.rstrip()[0:32]))

    # create files
    #
    fout = open(curr_sbf_path, 'w+')
    sbf.tofile(fout)
    fout.close()

    return 0

def make_sent_file(utc, out_dir, key_file, num_sentinels, safe=False,
        do_mse=False):
    """
    Create a sentinel file in out_dir for the given
    key_file and num_sentinels for the given utc.

    If do_mse is non-False, then add the MSE-mode sentinels to the
    file in addition to the ordinary TLS-mode sentinels (used by
    the TLS- and HTTP-based protocols).
    """

    sent_pname = sentinel_file_name(utc, out_dir)
    if safe and os.path.isfile(sent_pname):
        print "Skipping (%s)" % (sent_pname,)
        return

    print "Creating (%s)" % (sent_pname,)
        
    sent_tempname = sent_pname + '.tmp'
    sort_tempname = sent_tempname + '+'

    fout = open(sent_tempname, "w+")

    if do_mse:
        dhexp_pname = dhexp_file_name(utc, out_dir)

        if safe and os.path.isfile(dhexp_pname):
            print "Skipping (%s)" % (dhexp_pname,)
            return

        dhexp_out = open(dhexp_pname, "w+")

    time_str = gen_sentinels.create_date_hmac_str(utc)

    sentinels = list()

    for line in open(key_file, 'r'):
        key = line.split()

        for i in range (0, num_sentinels):
            sentinel = gen_sentinels.create_sentinel(key[1], i, time_str)
            fout.write(sentinel + '\n')

            # If we're doing an MSE sentinel for this key, do
            # it here.
            #
            if do_mse:
                (sentinel, dh_exp, dh_pub) = gen_sentinels.create_mse_sentinel(
                        key[1], i, time_str)
                fout.write(sentinel + '\n')

                dhexp_out.write('%s %s\n' % (sentinel[0:16], dh_exp))

    fout.close()

    if do_mse:
        dhexp_out.close()

    # allow this to use as much as 30% of the physical memory.
    # TODO: there should be a better way to throttle the memory use
    #
    bufsize = '30%'
    os.system('/usr/bin/sort -s -S %s -o %s %s' %
            (bufsize, sort_tempname, sent_tempname))
    os.remove(sent_tempname)

    # If we made it here successfully, rename the file to its final name.
    #
    os.rename(sort_tempname, sent_pname)

    return 0


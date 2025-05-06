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

import datetime
import re
import subprocess
import logging
import os
import sys

import cb.noc.file
import cb.noc.sentinel_hdrs

from cb.noc.cbbloom import CB_BloomFilter
from cb.util.dir_watcher import DirWatcherHelper

BLOOM_FILTER_PATH = '/tmp/sentinel_filter'
TMP_BLOOM_FILTER_PATH = BLOOM_FILTER_PATH + '.tmp'

def popen(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate()[0].strip()


class BloomWatcherHelper(DirWatcherHelper):
    """
    This class is a helper to DirWatcher
    It implements the necessary functions to load and unload
    filters, and it determines which of the available
    bloom filters need to be loaded
    """
    
    def __init__(self, load_callback):
        self.load_callback = load_callback
        super(BloomWatcherHelper, self).__init__()
        self.log = logging.getLogger('dr2dp.dr')
        self.is_clear = False

    def load(self, fname):
        """
        The DirWatcher has a new filter that we should be using.
        Copy the file over to where the DR expects to load it from
        And tell the DR to load it
        """

        print 'load fname %s' % fname

        fin = open(fname)
        bfilter = CB_BloomFilter.fromfile(fin)
        fin.close()

        # write the Bloom file to the temp file
        #
        fout = open(TMP_BLOOM_FILTER_PATH, 'w+')
        bfilter.tofile_simple(fout)
        fout.close()

        os.rename(TMP_BLOOM_FILTER_PATH, BLOOM_FILTER_PATH)

        # warm the cache before using the callback to tell the DR to load
        # the file.  The DR blocks while it's loading, so we want to make
        # this as quick as possible.  So, we open the file, read it, then
        # scan through all of it (to defeat mmap'd versions of read),
        # and close it.
        #
        # The cache is likely to be warm already, but this might help if
        # the file system cares about read-access vs write-access.
        #
        # A really clever optimizer would detect that we don't really
        # use the contents of the file, and optimize this whole thing away.
        # I don't think we're dealing with a really clever optimizer yet.
        #
        fin = open(BLOOM_FILTER_PATH)
        contents = fin.read()
        _junk = contents.split('q') # forces every byte to be examined
        fin.close()

        print "hash_size = %d, num_salts = %d" % (
               bfilter.hash_size, len(bfilter.salts))
        print 'salts = [%s]' % str(
                ['%.8x' % salt for salt in bfilter.salts])

        if self.load_callback != None:
            self.load_callback(bfilter.hash_size, bfilter.salts)
            self.is_clear = False

    def unload(self, fname):
        """
        Right now we only load/replace filters, but I don't believe
        we have an explicit unload.  (We can unload a filter, but
        it is not necessary if we are about to load a new one.)
        """
        pass

    def clear(self):

        # If we're already clear, then there's no need to send another
        # clear message.
        #
        if not self.is_clear:
            self.is_clear = True
            self.log.info('clear')
            print 'BloomWatcherHelper clear'

            # We explicitly tell the watcher thread that nothing is loaded.
            #
            self.watcher_thread.currently_loaded = set()

            self.load_callback(0, list())
        else:
            self.log.debug('already clear')

    def choose_fnames(self, fnames):
        """
        Given the list of available filters, which one do we want right now?

        Note: the pattern used to identify the current .sbf file is based
        on the names created in cb.noc.file.sentinel_bf_name(), and any
        changes in the format there must be reflected here.
        """

        utc = datetime.datetime.utcnow()
        prog = re.compile('cb-%s-g[0-9a-fA-F]{8}\.sbf$' %
                cb.noc.file.date_label_str(utc))

        matching_fnames = [ fname for fname in fnames if prog.match(fname) ]

        # If there are any matching names, choose the one with the highest
        # generation number (which will be lexically last)
        #
        if matching_fnames:
            matching_fnames.sort()
            matching_fnames.reverse()
            return list([matching_fnames[0]])
        else:
            # If we can't find any suitable files, then we need to clear.
            #
            self.clear()
            return list()


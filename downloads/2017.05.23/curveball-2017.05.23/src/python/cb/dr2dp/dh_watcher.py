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
DirectoryWatcherHelper for the "Bad Decoy Host" subnet files
"""

import ipaddr
import logging
import os
import re
import sys

from cb.util.dir_watcher import DirWatcherHelper

BAD_DH_LIST_PATH = '/tmp/bad_dh_list'
TMP_BAD_DH_LIST_PATH = BAD_DH_LIST_PATH + '.tmp'

class BadDecoyWatcherHelper(DirWatcherHelper):
    """
    DirectoryWatcherHelper subclass for "Bad Decoy Host" subnet files
    """

    def __init__(self, load_callback):
        self.load_callback = load_callback
        super(BadDecoyWatcherHelper, self).__init__()
        self.log = logging.getLogger('dr2dp.dr')

    def load(self, fname):
        """
        The DirWatcher has a new list of "bad" decoy hosts that
        we should be using.

        Copy the file over to where the DR expects to load it from
        And tell the DR to load it
        """

        print 'load fname %s' % fname

        # We verify the file before we invoke the callback
        # If there are any errors, then don't use the file.
        #
        try:
            lines = open(fname).readlines()
        except BaseException, exc:
            print >> sys.stderr, 'ERROR: [%s]' % str(exc)
            return

        lines = [ re.sub('#.*$', '', line).strip() for line in lines ]
        lines = [ line for line in lines if line ]

        errors = 0
        subnets = list()
        for line in lines:
            record = line.split()
            if len(record) < 2:
                print >> sys.stderr, (
                        'ERROR: badly formatted record [%s]' % line)
                errors += 1
            try:
                subnet = ipaddr.IPv4Network('%s/%s' % (record[0], record[1]))
                subnets.append(subnet)
            except BaseException, exc:
                print >> sys.stderr, 'ERROR: bad subnet [%s]' % str(record)
                errors += 1

        if errors:
            print >> sys.stderr, (
                    'ERROR: errors detected in DH list [%s]' % fname)
            return

        try:
            fout = open(TMP_BAD_DH_LIST_PATH, 'w+')
        except BaseException, exc:
            print >> sys.stderr, 'ERROR: [%s]' % str(exc)
            return

        for subnet in subnets:
            fout.write('%s %s\n' % (str(subnet.ip), str(subnet.netmask)))
        fout.close()

        os.rename(TMP_BAD_DH_LIST_PATH, BAD_DH_LIST_PATH)

        if self.load_callback != None:
            self.load_callback()

    def unload(self, fname):
        """
        Right now we only load/replace filters, but I don't believe
        we have an explicit unload
        """
        # TODO: We need to unload the current filter if nothing is available
        pass

    def choose_fnames(self, fnames):
        """
        Given the list of bad decoy host subnet filter files,
        choose the one with the highest generation number.
        """

        prog = re.compile('^cb-g[0-9a-fA-F]{8}\.bdh$')

        matching_fnames = [ fname for fname in fnames if prog.match(fname) ]

        if matching_fnames:
            matching_fnames.sort()
            matching_fnames.reverse()
            return list([matching_fnames[0]])
        else:
            return list()


if __name__ == '__main__':
    import time
    from cb.util.dir_watcher import DirWatcher

    def test_main():

        def test_helper():
            print ' FIRING TEST_HELPER'

        helper = BadDecoyWatcherHelper(test_helper)

        directory = '/tmp/dr/baddh'
        dir_watcher = DirWatcher(directory, helper, 5)

        snooze = 30
        print 'watching %s, sleeping %d seconds...' % (directory, snooze)
        time.sleep(snooze)

    test_main()

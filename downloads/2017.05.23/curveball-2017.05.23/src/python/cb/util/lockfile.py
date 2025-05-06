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
Very simple (and limited) lockfile class

Works for UNIX/Linux and Windows, but only for lockfiles on local
file systems; not expected to be generally portable, and not expected
to behave properly on NFS-mounted partitions.  Requires support for
the O_CREAT|O_EXCL flags to os.open, which apparently does not always
work properly over NFS.
"""

import logging
import os
import time

import cb.util.cblogging

class SimpleLockFile(object):
    """
    Very simple and limited lockfile class

    We don't expect it to take long to acquire the
    lockfile, so we poll briefly before giving up.
    """

    def __init__(self, lock_fname, max_probes=50, probe_delay=0.05):
        """
        lock_fname - the path to the lock file name.  If the path
        does not exist, or the parent directory cannot be written,
        attempts to acquire the lockfile will fail.

        max_probes - the maximum number of attempts to make to create
        the lockfile before giving up

        probe_delay - the delay (in seconds) between probes.
        """

        self.log = logging.getLogger('cb.util')

        self.lock_fname = lock_fname
        self.max_probes = max_probes
        self.probe_delay = probe_delay
        self.acquired = False

    def acquire(self):
        """
        Attempt to acquire the lockfile

        Return True if successful, False otherwise
        """

        # If we already hold the lock, there is no need to
        # reacquire it.  Return immediately.
        if self.acquired:
            return True

        lock_mode = os.O_CREAT | os.O_EXCL | os.O_WRONLY

        for attempt in range(0, self.max_probes):
            try:
                self.log.debug('attempt %d %s', attempt, self.lock_fname)
                lock_file = os.open(self.lock_fname, lock_mode, 0644)
                os.close(lock_file)
                self.acquired = True
                return True
            except OSError, exc:
                self.log.warn('attempt %d %s: %s', attempt, self.lock_fname,
                        str(exc))
                time.sleep(self.probe_delay)

        self.log.warn('failed to acquire lockfile: %s', self.lock_fname)
        return False

    def release(self):
        """
        Release the lockfile iff it is held by this instance
        """

        if not self.acquired:
            return

        try:
            os.remove(self.lock_fname)
            self.acquired = False
        except BaseException, exc:
            self.log.warn('could not delete lockfile %s: %s',
                    self.lock_fname, str(exc))

    def remove(self):
        """
        Release the lockfile (whether or not this instance holds it)

        Meant for initialization or cleanup
        """

        try:
            os.remove(self.lock_fname)
        except BaseException, exc:
            if os.path.exists(self.lock_fname):
                self.log.warn('could not delete lockfile %s: %s',
                        self.lock_fname, str(exc))

        self.acquired = False

if __name__ == '__main__':
    import tempfile

    def test_main():
        """
        Simple test driver: creates two locks using the same
        lockfile, acquires it via one of the locks, then attempts
        to acquire it via the second, which should time out.
        Then the first lock is release, and the second should
        then be able to acquire it.
        """

        path = os.path.join(tempfile.gettempdir(), 'xxx.lck')
        errors = 0

        lf1 = SimpleLockFile(path)
        lf2 = SimpleLockFile(path)

        lf1.remove() # just in case

        if not lf1.acquire():
            print "ERROR: could not acquire lf1"
            errors += 1
        else:
            print "SUCCESS: acquired lf1"

        if lf2.acquire():
            print "ERROR: should not have acquired lf2"
            errors += 1
        else:
            print "SUCCESS: lf2 is already locked"

        lf1.release()

        if not lf2.acquire():
            print "ERROR: could not acquire lf2"
            errors += 1
        else:
            print "SUCCESS acquired lf2"

        lf2.release()

        if errors:
            print 'FAILED'
        else:
            print 'SUCCESS'

        return errors

    exit(test_main())

#!/usr/bin/env python
#
# This material is funded in part by a grant from the United States
# Department of State. The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of the United States Department of State.
#
# Copyright 2016 - Raytheon BBN Technologies Corp.
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
ProcWatcher is a utility for watching a process and running a helper
function when it dies.  The functionality and interface are copied
from the DirWatcher, although this is considerably simpler (because
a directory might change any number of times, but a process can only
die once).

To use, create a class that implement the ProcWatcherHelper interface.

The ProcWatcher "watches" a subprocess.Popen reference, periodically
polling the process to see whether it has exited.  If it has, then it
invokes the exited method of the helper class.
"""

import logging
import threading
import time

import cb.util.cblogging

class ProcWatcherHelper(object):
    """
    """

    def __init__(self):
        self.watcher_thread = None # filled in by the watcher thread

    def exited(self, subproc, exit_code):
        """
        """

        pass


class ProcWatcher(object):
    """
    Toplevel class for the directory watcher
    """

    def __init__(self, watched_proc, helper):

        self.logger = logging.getLogger('cb.util')

        self.watched_proc = watched_proc
        self.helper = helper

        self.watcher_thread = ProcWatcherThread(watched_proc, helper)

        self.watcher_thread.start()


class ProcWatcherThread(threading.Thread):
    """
    Thread that performs the polling and invokes the methods in the
    helper object.
    """

    def __init__(self, watched_proc, helper):
        """
        watched_proc: the subprocess.Popen reference to monitor

        helper: an instance of an object that obeys the
        ProcWatcherHelper interface, as defined above
        """

        threading.Thread.__init__(self)
        self.daemon = 1

        self.logger = logging.getLogger('cb.util')

        # The directory to scan for new sentinel files
        #
        self.watched_proc = watched_proc

        self.helper = helper

    def run(self):
        """
        Wait for the process to die.

        If the directory is not specified, fail.
        If the directory is specified but does not
        exist, patiently wait for it to be created.
        """

        try:
            self.logger.info('waiting for subprocess')
            exit_code = self.watched_proc.wait()
            self.logger.info('subprocess has exited')
            if self.helper:
                self.helper.exited(self.watched_proc, exit_code)
        except BaseException:
            pass


if __name__ == '__main__':

    class TestProcWatcherHelper(ProcWatcherHelper):
        """
        Test subclass for the ProcWatcherHelper
        """

        def __init__(self):
            super(TestProcWatcherHelper, self).__init__()

        def exited(self, proc, exit_code):
            print 'TestProcWatcher Exited:   [%d]' % exit_code


    def main():
        """
        Basic test driver for the directory watcher

        Create a directory named 'dd', and then populate it with
        different subsets of {foo, bar} to see what happens in different
        cases.
        """

        helper = TestProcWatcherHelper()
        ProcWatcher('dd', helper, 1)

        time.sleep(10)
        return 0

    exit(main())

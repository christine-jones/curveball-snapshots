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
DirWatcher is a utility for watching a directory for the addition
of new files, and then triggering processing (called "load" and "unload")
on those files.

To use, create a class that implement the DirWatcherHelper interface.

The DirWatcher "watches" a directory, periodically polling the contents
of the directory to find the list of files present in the directory.
It then determines which of the files, if any, should be "chosen" (via
the "choose_fname" method of the helper) to be "loaded".  Any other
previously loaded files are not chosen are "unloaded".

Note that the chosen files may include files that are not present;
the mechanism for defining which files are "chosen" may or may not
depend on the actual list of files.

For example, say we have parameters for the system that change
for each day of the week, at midnight.  We could put these files into
the watched directory, with names "Monday" .. "Sunday", and have the
chose_fname method choose only the name of the current day of the week.
The Monday file will be loaded at the start of Monday, and remain
loaded all day, and then it will be unloaded at the start of Tuesday,
and the Tuesday file will be loaded. 

"""

import logging
import os.path
import threading
import time

import cb.util.cblogging
import cb.bp

class DirWatcherHelper(object):
    """
    This class implements the methods (and any internal state
    needed by those methods) needed to load and unload files
    and to determine which files should be active.
    """

    def __init__(self):
        self.watcher_thread = None # filled in by the watcher thread

    def load(self, fname):
        """
        Load the specified file

        If any exception is raised, then the named file is not
        considered to have been successfully loaded.
        """

        pass

    def unload(self, fname):
        """
        Unload the specified file

        If any exception is raised, then the named file is not
        considered to have been successfully unloaded.
        """

        pass

    def clear(self):
        """
        Invoked when there are no loaded files at all.

        Some watchers do special things when there is nothing to load
        (or everything loaded has been unloaded), but the default
        behavior is to do nothing.
        """

        pass

    def choose_fnames(self, fnames):
        """
        Choose the set of fnames that should be loaded, if they
        are not already loaded, and return as a list or set.

        The list of currently-available fnames is provided, but the
        implementation can ignore this list.  For example, this method can
        always return ["foo"], (or in our typical case, a list of filenames
        constructed as a function of the current date/time)

        The DirWatcher will do the right thing if the returned
        files are not available.
        """

        # This method should be overridden!
        #
        return fnames

class DirWatcher(object):
    """
    Toplevel class for the directory watcher
    """

    # Polling interval, in seconds.
    #
    DEFAULT_POLL_INTERVAL = 5

    def __init__(self, watched_dname, helper,
            poll_interval=DEFAULT_POLL_INTERVAL):

        self.logger = logging.getLogger('cb.util')

        self.watched_dname = watched_dname
        self.helper = helper
        self.poll_interval = poll_interval

        if not os.path.exists(watched_dname):
            self.logger.error(
                    "DirWatcher: %s: no such file or directory" % watched_dname)

        self.watcher_thread = DirWatcherThread(watched_dname,
                                               helper,
                                               poll_interval)

        if self.helper:
            self.helper.watcher_thread = self.watcher_thread

        self.watcher_thread.start()


class DirWatcherThread(threading.Thread):
    """
    Thread that performs the polling and invokes the methods in the
    helper object.
    """

    def __init__(self, watched_dname, helper,
            poll_interval=DirWatcher.DEFAULT_POLL_INTERVAL):
        """
        helper: an instance of an object that obeys the
        DirWatcherHelper interface, as defined above

        watched_dname: the name of the directory to watch
        for new files

        poll_interval: interval, in seconds, between polls
        """

        threading.Thread.__init__(self)
        self.daemon = 1

        self.logger = logging.getLogger('cb.util')

        # The directory to scan for new sentinel files
        #
        self.watched_dname = watched_dname

        self.helper = helper

        # The names of the currently loaded update files.
        #
        self.currently_loaded = set()

        self.poll_interval = poll_interval

    def run(self):
        """
        Poll the directory, watching for new files.
        Load each new file in when it becomes due.

        If the directory is not specified, fail.
        If the directory is specified but does not
        exist, patiently wait for it to be created.
        """

        while True:
            self.scan_dir()
            time.sleep(self.poll_interval)

    def scan_dir(self):
        """
        Scan the directory, looking for files, letting the helper
        choose the ones it wants, and then loading/unloading to
        make the state with the helper's chosen set of files.
        """

        if not os.path.isdir(self.watched_dname):
            self.logger.debug('watched_dname (%s): missing' %
                    (self.watched_dname,))
            return 
 
        avail_fnames = os.listdir(self.watched_dname)
        if not avail_fnames:
            self.logger.debug('watched_dname (%s): no files' %
                    (self.watched_dname,))
            return

        # Find what files we should have loaded right now.
        #
        curr_update_fnames = self.helper.choose_fnames(avail_fnames)

        # Figure out what files we have loaded, if any, that
        # we should not longer have loaded, and purge them.
        #
        obsolete_fnames = [fname for fname in self.currently_loaded
                if (not fname in curr_update_fnames)]

        for obsolete_fname in obsolete_fnames:
            if obsolete_fname in avail_fnames:
                path = os.path.join(self.watched_dname, obsolete_fname)

                self.logger.info('unload (%s)' % (obsolete_fname,))
                try:
                    self.helper.unload(path)
                except BaseException as exc:
                    self.logger.warn('failed to unload (%s): %s' %
                            (obsolete_fname, str(exc)))
                else:
                    self.currently_loaded.discard(obsolete_fname)
            else:
                self.logger.warn('cannot unload (%s): not avail' %
                        (obsolete_fname,))

        # Figure out what files should be loaded, but are not, if any.
        #
        wanted_fnames = [fname for fname in curr_update_fnames
                if (not fname in self.currently_loaded)]

        for wanted_fname in wanted_fnames:
            if wanted_fname in avail_fnames:
                path = os.path.join(self.watched_dname, wanted_fname)

                self.logger.info('load (%s)' % (wanted_fname,))
                try:
                    self.logger.debug(
                            'DirWatcherThread calling self.helper.load(%s)' %
                            path)
                    self.helper.load(path)
                except BaseException as exc:
                    self.logger.warn('failed to load (%s): %s' %
                            (wanted_fname, str(exc)))
                else:
                    self.currently_loaded.add(wanted_fname)
            else:
                self.logger.warn('cannot load (%s): not avail' %
                        (wanted_fname,))

        # For some watchers, it is useful to know when there's nothing
        # loaded at all.
        #
        if len(self.currently_loaded) == 0:
            self.helper.clear()

if __name__ == '__main__':

    class TestDirWatcherHelper(DirWatcherHelper):
        """
        Test subclass for the DirWatcherHelper

        load, unload, and clear just print what they would do.

        choose_fnames conjures up names out of thin air, based
        on the number of times the method is invoked, to show
        how the watcher reacts.
        """

        def __init__(self):
            super(TestDirWatcherHelper, self).__init__()

            # for debugging only...
            self.count = 0

        def load(self, fname):
            print 'TestDirWatcher Load:   [%s]' % fname

        def unload(self, fname):
            print 'TestDirWatcher Unload: [%s]' % fname

        def clear(self):
            print 'TestDirWatcher Clear'

        def choose_fnames(self, fnames):

            # Default action for debugging only
            self.count += 1
            if not fnames:
                print 'nothing to choose from...'
                return list()
            elif self.count == 1:
                print 'foo'
                return list(['foo'])
            elif self.count == 2:
                print 'foo, bar'
                return list(['foo', 'bar'])
            elif self.count == 3:
                print 'bar'
                return list(['bar'])
            else:
                print '<none>'
                return list()


    def main():
        """
        Basic test driver for the directory watcher

        Create a directory named 'dd', and then populate it with
        different subsets of {foo, bar} to see what happens in different
        cases.
        """

        helper = TestDirWatcherHelper()
        DirWatcher('dd', helper, 1)

        time.sleep(10)
        return 0

    exit(main())

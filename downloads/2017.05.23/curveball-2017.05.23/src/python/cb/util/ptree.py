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
Routines to find the process tree rooted at a given pid, and kill all the
descendants of a process tree.

Python's subprocess module does not grok process groups, and therefore doing
something that would seem straightforward, such as putting all the children of a
process into a process group and then signalling them all with a single call is
not straightforward AT ALL.  This module attempts to smooth over some of these
issues.
"""

import os
import subprocess

import cb.util.platform

def find_ptree(pid, only_mine=True):
    """
    Return a list of the pid and all of its descendants, in pre-order.

    If only_mine is True, then just use 'ps a' to find the pids.
    If only_mind is False, then use 'ps ax' to find pids owned
    by other users.  (On Android, only_mine is ignored)
    """

    def add_children(families_map, root_pid):
        """
        Recursive function that computes the transitive closure of
        processes that are descendants of pid, according to the
        parent->children map provided as families.
        """

        found_pids = list()

        if not root_pid in families:
            return found_pids

        children = list(families_map[root_pid])

        for child in children:
            found_pids += list([child])
            found_pids += add_children(families, child)

        return found_pids

    if not cb.util.platform.PLATFORM in ['android', 'win32']:
        col_flags = ['-o', 'ppid=,pid=']

        if only_mine:
            cmd = ['ps', 'a'] + col_flags
        else:
            cmd = ['ps', 'ax'] + col_flags

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        (stdout_txt, _stderr_txt) = proc.communicate()

        # This conversion is a NOP in almost all cases, but it
        # convinces pylint that stdout_txt really is a string of
        # some kind.
        #
        stdout_txt = str(stdout_txt)
        lines = stdout_txt.split('\n')

        parents = [ [ int(val) for val in line.split() ]
                for line in lines
                        if line ]

    else:
        # Android and Windows are quirky and have crippled ps impls.
        # If we're on Android, we can get what we need from the
        # BusyBox version of ps, but it's in a different format.
        # On Windows, the format is different yet again.

        cmd = ['ps']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        (stdout_txt, _stderr_txt) = proc.communicate()

        # See above.
        stdout_txt = str(stdout_txt)
        lines = stdout_txt.split('\n')

        # throw away the headings line
        lines = lines[1:]

        # pluck out the fields we need
        parents = list()
        for line in lines:
            if not line:
                continue
            fields = line.split()
            if cb.util.platform.PLATFORM == 'win32':
                parents.append([int(fields[1]), int(fields[0])])
            else:
                parents.append([int(fields[2]), int(fields[1])])

    families = {}
    for (parent, child) in parents:
        if parent in families:
            families[parent].add(child)
        else:
            families[parent] = set([child])

    pids = list([pid])
    pids += add_children(families, pid)

    return pids

def kill_ptree(pid, signal, only_mine=True):
    """
    Send the given signal to the given pid and all of its descendants
    (from the bottom up of the process tree).
    """

    pids = find_ptree(pid, only_mine)
    if not pids:
        return None

    # Reverse the list, to kill the pids in post-order.
    #
    pids.reverse()
    for pid in pids:
        try:
            os.kill(pid, signal)
        except OSError, exc:
            if exc.errno == 3:
                pass
            else:
                print 'WHOOPS %d: %s' % (pid, str(exc))
        except BaseException, exc:
            print 'UNEXPECTED %d: %s' % (pid, str(exc))

if __name__ == '__main__':
    import sys

    def main():
        if len(sys.argv) != 2:
            print 'ERROR: usage %s PID' % sys.argv[0]
            return -1

        pids = find_ptree(int(sys.argv[1]))

        print 'descendants of %s: %s' % (sys.argv[1], str(pids))
        for pid in pids:

            # the output of ps is different on android.
            #
            if cb.util.platform.PLATFORM == 'android':
                cmd = 'ps | awk \'{$1=""; print}\' | grep "^\ *%d\ "' % pid
            else:
                cmd = 'ps | grep "^\ *%d\ "' % pid

            os.system(cmd)

        return 0

    exit(main())

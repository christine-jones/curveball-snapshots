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

import os
import signal
import socket
import subprocess
import sys
import time

import cb.util.ptree

class CTMClient(object):

    STATES = [
            'request', 'started', 'failed', 'working',
            'completed', 'terminate', 'terminated'
            ]

    def __init__(self, basedir=None):

        if not basedir:
            basedir = '/tmp/%s/ctm' % socket.gethostname()

        self.basedir = basedir

        # print 'CTM basedir = [%s]' % self.basedir

        if not os.path.isdir(self.basedir):
            os.makedirs(self.basedir)

        # a map from the files to their current directories
        self.all_tasks = {}
        self.check_basedir()

    def check_basedir(self):
        """
        check that the basedir exists.  raise an exception if not
        """

        if not os.path.isdir(self.basedir):
            raise BaseException('Missing basedir %s' % self.basedir)

    def _change_state(self, task, new_state):
        """
        Update the directory and self.all_tasks
        """

        if not new_state in self.STATES:
            print 'unknown state [%s]' % new_state
            return

        new_name = os.path.join(self.basedir, new_state, task)

        # TODO: we permit change_state to bring files into existance.
        # Is that OK, or should it only be allowed to change states?
        #
        if not task in self.all_tasks:
            open(new_name, 'w').close()
        else:
            old_state = self.all_tasks[task]
            old_name = os.path.join(self.basedir, old_state, task)

            if (new_name != old_name) and os.path.isfile(old_name):
                os.rename(old_name, new_name)

        self.all_tasks[task] = new_state

    def note_request(self, task):
        self._change_state(task, 'request')

    def note_started(self, task):
        self._change_state(task, 'started')

    def note_failed(self, task):
        self._change_state(task, 'failed')

    def note_working(self, task):
        self._change_state(task, 'working')

    def note_completed(self, task):
        self._change_state(task, 'completed')

    def note_terminate(self, task):
        self._change_state(task, 'terminate')

    def note_terminated(self, task):
        self._change_state(task, 'terminated')

    def terminate_task(self, task):
        """
        Update the directory and self.all_tasks
        """
        pass

    def in_state(self, state):
        tasks = set()

        for candidate in self.all_tasks:
            if self.all_tasks[candidate] == state:
                tasks.add(candidate)

        return tasks

    def get_state(self, task):

        if task in self.all_tasks:
            return self.all_tasks[task]
        else:
            return None

    def get_file_contents(self, task):
        """
        Return the contents of the task file, if there is one.
        If not, then return None.
        """

        if not task in self.all_tasks:
            return None
        else:
            state = self.all_tasks[task]
            path = os.path.join(self.basedir, state, task)
            return open(path).read()

    def scandirs(self):
        """
        Scan through all of the directories, rebuilding self.all_tasks.

        Useful if there is some other app that is adding requests or
        deleteing complete or failed tasks.

        Returns a tuple (request, terminate) listing any new tasks in
        the request or terminate subdirectories

        Intended to be invoked periodically.
        """

        # First figure out what there is now, before we update anything.
        #
        old_request = set()
        old_terminate = set()

        for task in self.all_tasks:
            if self.all_tasks[task] == 'terminate':
                old_terminate.add(task) 
            elif self.all_tasks[task] == 'request':
                old_request.add(task) 

        # Now it's time to do the update.
        old_all_tasks = self.all_tasks

        self.all_tasks = {}

        # TODO: doesn't check for things in more than one state.
        # (sometimes this is OK, other times not)
        #
        for subdir in self.STATES:
            if os.path.isdir(os.path.join(self.basedir, subdir)):
                for _root, _dirs, files in os.walk(
                        os.path.join(self.basedir, subdir)):
                    for fname in files:
                        self.all_tasks[fname] = subdir
                    break
            else:
                print 'missing dir for %s' % subdir

        new_request = set()
        new_terminate = set()

        for task in self.all_tasks:
            if self.all_tasks[task] == 'terminate':
                new_terminate.add(task) 
            elif self.all_tasks[task] == 'request':
                new_request.add(task) 

        return (new_request - old_request), (new_terminate - old_terminate)


class CTMUtility(CTMClient):

    def __init__(self, basedir=None):
        CTMClient.__init__(self, basedir)

    def check_basedir(self):
        """
        make sure that the basedir exists.  Create it if necessary.
        """

        # if the subdir exists, destroy it

        if os.path.isdir(self.basedir):
            os.system('rm -rf %s/' % self.basedir)

        for subdir in self.STATES:
            path = os.path.join(self.basedir, subdir)
            os.system('/bin/mkdir -p %s' % path)

class LauncherClient(object):

    def __init__(self, basedir=None):
        self.tasks = CTMClient(basedir)

    def add_task(self, task, cmdline):
        fout = open(os.path.join(self.tasks.basedir, 'request', task), 'w+')
        fout.write(cmdline)
        fout.close()

    def request_ct(self, socks_port, tunnel_port, decoy_host, protocol,
            use_keys):
        """
        Request a new ct

        We only permit the user to specify the decoy host, not a host
        and a port, because we can only tolerate set port/protocol
        combinations.  Therefore the protocol determines the port.
        """

        # curveball-client can get confused if it is executed from the
        # wrong directory.  This shouldn't normally matter, but make
        # sure that we use the correct directory.  This only works, of
        # course, if the script we are running is in the correct
        # directory!
        #
        mydir = os.path.normpath(
                os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))

        cmd = ('cd %s ; ./curveball-client ' % mydir)
        cmd += ('--proxy %d ' % socks_port)
        cmd += ('--tunnel-port %d ' % tunnel_port)

        if use_keys:
            cmd += '-x ' # use real sentinels

        if protocol == 'http':
            cmd += '-w '
            port = 80
        elif protocol == 'httpu':
            cmd += '-w -u '
            port = 8080
        elif protocol == 'https':
            port = 443
        else:
            print 'Unsupported protocol detected [%s]' % protocol
            return

        cmd += ('-d %s:%d ' % (decoy_host, port))

        task_name = str(socks_port)

        self.add_task(task_name, cmd)
        return task_name

    def ready_ct(self, task_name):
        """
        Return True if the CT is "ready".
        """

        sock = socket.socket()

        try:
            sock.connect(('', int(task_name)))
        except BaseException, exc:
            print 'Not listening: task %s: %s' % (task_name, str(exc))
            return False

        try:
            sock.send('is anyone listening yet?')
        except BaseException, exc:
            print 'Listening but not ready: task %s: %s' % (
                    task_name, str(exc))
            return False

        try:
            print 'waiting for return: task %s' % (task_name)
            sock.settimeout(0.2)
            res = sock.recv(4 * 1024)
        except BaseException, exc:
            print 'return failed %s: %s' % (
                    task_name, str(exc))
            return False
        else:
            res = [ '%.2x' % byte for byte in res ]

        return True


class LauncherUtility(LauncherClient):

    def __init__(self, basedir=None):
        self.tasks = CTMUtility(basedir)
        self.procs = {}

    def runner(self):
        (todo, tokill) = self.tasks.scandirs()

        if todo:
            print 'Tasks to start: %s' % str(todo)

        for task in todo:
            cmdline = self.tasks.get_file_contents(task)
            cmdline.strip()

            print 'Starting task [%s] [%s]' % (task, cmdline)
            self.procs[task] = subprocess.Popen(cmdline, shell=True,
                    close_fds=True)

            self.tasks.note_working(task)

        if tokill:
            print 'Tasks to kill: %s' % str(tokill)
            time.sleep(0.5) # A little breaking space.

        for task in tokill:
            if not task in self.procs:
                print 'Nothing known about task [%s]: cannot terminate' % task
            else:
                if not task in self.procs:
                    print 'No proc found for %s' % task
                    continue

                proc = self.procs[task]
                cb.util.ptree.kill_ptree(proc.pid, signal.SIGTERM)

                # We assume that kill_tree always works.  It might fail, but
                # detecting failure reliably is a maze of edge cases.
                #
                print 'Terminated [%s]' % task
                del self.procs[task]
                self.tasks.note_terminated(task)

        dead_tasks = set()
        live_tasks = set()
        for task in self.procs:
            proc = self.procs[task]
            poll = proc.poll()
            if not poll is None:
                if poll != 0:
                    print 'Task %s failed' % task
                    self.tasks.note_failed(task)
                else:
                    print 'Task %s completed' % task
                    self.tasks.note_completed(task)

                # The task is dead; get rid of it.
                dead_tasks.add(task)
            else:
                live_tasks.add(task)

        # print 'Running tasks: %s' % str(sorted(live_tasks))

        for task in dead_tasks:
            del self.procs[task]

    def live_tasks(self):
        live_tasks = set()

        for task in self.procs:
            proc = self.procs[task]
            poll = proc.poll()
            if poll is None:
                live_tasks.add(task)
            else:
                print 'Detected dead task [%s]' % task

        return sorted(live_tasks)


if __name__ == '__main__':

    def test_main():
        util = LauncherUtility('fred')

        client = LauncherClient('fred')

        client.add_task('00', 'echo hello')
        # print util.tasks.scandirs()

        util.runner()

        time.sleep(3)
        util.runner()

        time.sleep(1)
        util.runner()

        print client.tasks.scandirs()

    exit(test_main())

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

""" Helper classes to run Curveball experiments on DETER """

import threading
import readline
import pexpect
import atexit
import socket
import subprocess
import glob
import os

# FIXME: Note that hostnames are case-insensitive, but our comparisons
# are case-sensitive.  Don't use caps in hostnames, or this could break.
#
DETERLAB_SUFFIX = 'isi.deterlab.net'
SAFERLAB_SUFFIX = 'safer.' + DETERLAB_SUFFIX
DETERLAB_USERS = 'users.' + DETERLAB_SUFFIX

# If we're inside DETER, then we don't need to use an ssh proxy to access
# our experiment hosts (and it won't succeed if we try).  If we're outside
# DETER, then the opposite is true.
# 
if socket.gethostname().endswith(SAFERLAB_SUFFIX):
    SAFERLAB_SSH_PROXY = None
else:
    SAFERLAB_SSH_PROXY = DETERLAB_USERS

class ExpectView(object):
    def __init__(self):
        self.session = None
        
    def expect(self, cmdstr, timeout=None):
        """ Run an expect command """
        self.session.expect(cmdstr, timeout=timeout)
#        print "a"
#        print self.session.before
#        print "b"
#        print self.session.buffer
#        print "c"
#        print self.session.after
#        print "d"
        return (self.session.before, self.session.buffer, self.session.after)
        
    def run(self, cmd, wait=False):
        """ Run a command """

        if wait:
            self.run('ALLDONE=CURVEDONE!')
            self.expect('CURVEDONE!')
            self.run('echo $ALLDONE')
            self.expect('CURVEDONE!')
            cmd = '(%s) ; echo $ALLDONE' % cmd
        if(os.getenv('CB_DEBUG')):
            name = getattr(self, 'host', '(host unknown)')
            print '%s: Sending command [%s]' % (name, cmd)


        self.session.sendline(cmd)
        #print cmd
        if wait:
            self.session.expect("CURVEDONE!", timeout=1000)
        
    def controlc(self):
        """ Send a control+c to the other end """
        self.session.sendcontrol('c')
    
    def close(self):
        """ Close the connection """
        self.session.close()
        
    def interact(self):
        self.session.interact()
            
    def commandeer(self):
        self.interact()
        
    def connect(self):
        raise Exception("Unimplemented Function: connect")
        


class ExpectCORE(ExpectView):
    """ CORE: Connects to Linux Network Namespace containers
    created by CORE over python expect. Provides useful functions
    for running commands over the session and reading output """
    
    def __init__(self, host, connect=None, prefix=None):
        super(ExpectCORE, self).__init__()
        self.host = host
        self.path = None
        self.prefix = prefix
        
        if connect:
            self.connect()
            
    def connect(self):
        dirs = glob.glob('/tmp/pycore*')
        if len(dirs) == 0:
            raise Exception("Could not connect to CORE, is it running?")
        # Now find a pycore session that has a file for our host in it
        if len(dirs) > 1:
            raise Exception("Too many /tmp/pycore* directories -- multiple cores?")

        for directory in dirs:
            files = glob.glob('%s/%s' % (directory, self.host))
            if files:
                self.path = '%s/%s' % (directory, self.host)
                break
        if not self.path:
            raise Exception(
                    "Could not find find a running CORE host named %s" %
                    self.host)
        
        cmd = 'vcmd -c %s -- bash' % self.path
        self.session = pexpect.spawn(cmd)
        
        
        # Set the PYTHONPATH
        if self.prefix:
            self.run('export PYTHONPATH=%s/python/:$PYTHONPATH' % self.prefix)
        
        

class ExpectSSH(ExpectView):
    """ SSH: Connects to a host via an SSH over python expect.
    Provides useful functions for running commands over the 
    session and reading output
    
    @param host: machine to connect to (fully qualified name)
    @param proxy: proxy the ssh connection through another machine?
    @param connect: connect right away?
    """
    def __init__(self, host, proxy=None, connect=None):
        super(ExpectSSH, self).__init__()
        self.host = host
        self.proxy = proxy

        if connect:
            self.connect()
        
    def connect(self):
        """ connects to the host """
        opts = ''
        if self.proxy:
            opts += "-o 'ProxyCommand ssh %s nc %s %%p'" % (self.proxy, 
                                                            self.host)
        opts += " -o 'StrictHostKeyChecking no'"
        
        cmd = 'ssh %s %s' % (opts, self.host)
        self.session = pexpect.spawn(cmd)

        self.run('echo HI THERE')
        try:
            self.expect('HI THERE', 30)
            self.expect('HI THERE', 30)
        except (pexpect.EOF, pexpect.TIMEOUT):            
            print "Trouble connecting to host %s" % self.host
            exit(1)
        #self.set_prompt()
    


class ConnectThread(threading.Thread):
    def __init__(self, ssh):
        self.ssh = ssh
        threading.Thread.__init__(self)

    def run(self):
        self.ssh.connect()
        print "connected to %s" % self.ssh.host


def one_shot_ssh(host, cmd, proxy=None):
    """ Connect to host, run the cmd, disconnect,
    and then return (exit_status, stdout, stderr) """
    
    opts = "-o 'StrictHostKeyChecking no'"
    if proxy:
        opts += "-o 'ProxyCommand ssh %s nc %s %%p'" % (proxy, host)

    proc = subprocess.Popen("ssh %s %s '%s'" % (opts, host, cmd),
                            shell=True, 
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    return (proc.returncode, out, err)
    
    
     

class CurveballExperiment(object):
    """ A class to facilitate running experiments
    on DETER.  It manages the SSH connections to your 
    machines and runs an interactive command prompt.
    
    @param transport: how pexpect will connect to your experiment, either 'core' or 'ssh'
    @param servers: a list of server names, such as ['dp','dr',...]
    @param experiment: the name of the deter experiment, e.g., 'helloworld'
    @param cmds: a dictionary of cmds -> help strings.  These are the commands
                available at the interactive prompt.    
    """
    
    
    def __init__(self, transport, servers, exp_name, cmds, prefix):
        self.connections = {}
        self.servers = servers
        self.exp_name = exp_name
        self.cmds = cmds

        if prefix[0] != '/':
            # Relative path..
            prefix = os.getcwd() + '/' +  prefix
            
        self.prefix = prefix
                    
        self.transport = transport
        self.launched = False
        atexit.register(self.disconnect)

        # Load our readline history
        histfile = '.%s_hist' % exp_name
    
        try:
            readline.read_history_file(histfile)
        except IOError:
            pass
        
        atexit.register(readline.write_history_file, histfile)


    def launch_core(self):
        self.launched = True
        pass
    
    def launch_ssh(self):
        users = ExpectSSH(DETERLAB_USERS)
        pass

    def connect(self, args=None):
        """ connects to all servers """
        if self.transport == 'ssh':
            threads = []
            for server in self.servers:           
                host = "%s.%s.%s" % (server, self.exp_name, SAFERLAB_SUFFIX)
                ssh = ExpectSSH(host, proxy=SAFERLAB_SSH_PROXY)
                self.connections[server] = ssh
                thread = ConnectThread(ssh)
                thread.start()
                threads.append(thread)
    
            for thread in threads:
                thread.join()
                
        elif self.transport == 'core':
            for server in self.servers:
                self.connections[server] = ExpectCORE(server,
                        connect=True, prefix=self.prefix)
                
                
        else:
            raise Exception("Unknown Transport")
        
        print "Connected to all servers"
            
    def disconnect(self, args=None):
        """ disconnects ssh to all servers """
        for (name, connection) in self.connections.iteritems():
            print "Disconnecting from %s" % name
            connection.close()
        self.connections = {}
        print "Disconnected"
    
    def create_spare(self, host):
        """ sometimes you need multiple connections to a host,
        this function creates one on the fly """
        
        if self.transport == 'ssh':
            host = '%s.%s.%s' % (host, self.exp_name, SAFERLAB_SUFFIX)
            return ExpectSSH(host, proxy=SAFERLAB_SSH_PROXY, connect=True)
        elif self.transport == 'core':
            return ExpectCORE(host, connect=True, prefix=self.prefix)
            
    def _prompt(self):        
        """ print available commands """
        print ""
        print "Available commands:"
        for (cmd, helpstr) in self.cmds.iteritems():
            print "%s -- %s" % (cmd, helpstr)

        print ""           
    
    def interact(self, args=None):
        """ Run an interactive session.  Prompts the user
        for a command, runs it, and prompts again in a loop.
        The acceptable commands are passed in in __init__.
        It is assumed that the commands are function names
        on the class that inherits CurveballExperiment. """
        
        while True:

            # eof is the same as 'exit'
            try:
                self._prompt()
                user_input = raw_input("# ").strip()
            except EOFError:
                user_input = 'exit'

            found = False
            for cmd in self.cmds:
                if user_input.startswith(cmd):
                    args = user_input[len(cmd):].strip()
                    getattr(self, cmd)(args)
                    found = True
            if not found:
                print "unknown command: %s" % user_input
    
    def run(self, host, cmd, wait=False):
        """ Runs a command on a host (uses pexpect.sendline) """
        self.connections[host].run(cmd, wait=wait)
    
    def expect(self, host, cmd_str, timeout=None):
        """ Runs pexpect on a host """
        return self.connections[host].expect(cmd_str, timeout=timeout)
     
    def commandeer(self, host):
        if not host in self.connections:
            print "Unknown host"
            return
        self.connections[host].interact()

    def add_sentinels(self, nhours):
        if not nhours:
            nhours = 12

        try:
            nhours_num = int(nhours)
        except ValueError:
            print 'Invalid number of hours (%s)' % str(nhours)
            return

        if nhours_num < 1:
            print 'Invalid number of hours (%d) must be > 0' % nhours_num
            return

        self.add_sentinels_worker(nhours_num)

    def add_sentinels_worker(self, num_hours=12):
        """
        Add sentinels for up to num_hours in the future.
        """
        # TODO: only the default parameters are permitted, except for the
        # length (which is bumped up to num_hours)

        # TODO: add way to control num_hours.
        print 'Adding sentinels and Bloom filters'
        print 'Warning: num_hours is ignored by cbnoc-keymanager'
        key_setup_script = os.path.join(self.prefix, 'scripts',
                'cbnoc-keymanager')
        os.system('sudo %s push' % key_setup_script)
        print "Finished adding sentinels..."

    def controlc(self, host):
        """ Sends a ctrl+c command to the host """
        self.connections[host].controlc()

    

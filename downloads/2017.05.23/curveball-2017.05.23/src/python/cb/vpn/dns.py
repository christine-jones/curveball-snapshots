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
Helper classes for dealing with DNS configuration
"""

import logging
import os
import re

# Imported for effect.
import cb.util.cblogging

class DnsManager(object):
    """
    Interface for DNS management tasks.

    Use as the base class for all DnsManager implementations
    """

    def __init__(self):
        pass

    def fetch_state(self):
        """
        fetch the current, running state of the DNS config

        Return True if successful, False otherwise
        """
        pass

    def restore_state(self):
        """
        restore the original state of the DNS config
        (the config when this instance was create)

        Return True if successful, False otherwise
        """
        pass

    def get_current_servers(self):
        """
        Return a list of the current DNS nameservers
        """
        pass

    def clear_servers(self):
        """
        Remove all DNS nameservers from the active config

        Return True if successful, False otherwise
        """
        pass

    def add_servers(self, server_list):
        """
        Add new servers to the active config

        Adding a server may have no effect if the server
        is already present in the config.

        Return True if successful, False otherwise
        """
        pass


class DnsManagerLinux(DnsManager):
    """
    Implementation of the DnsManager interface for linux.

    Will also work for many generic Unix impls that use
    resolv.conf to handle all of the DNS config.
    """

    CONFIG_FILE = '/etc/resolv.conf'

    def __init__(self, config_file=CONFIG_FILE):
        """
        config_file - the config file to read and/or modify.

        The config_file should already exist; these methods may fail (or raise
        exceptions) it is not present and readable.  Some of the methods will
        also fail if the user does not have adequate permissions to write the
        config_file.

        These methods do not generally raise exceptions.  They signal failure
        via return codes.
        """

        DnsManager.__init__(self)

        self.logger = logging.getLogger('cb.vpn')
        self.logger.debug('Initializing DNS manager for [%s]' %
                (config_file,))

        self.config_file = config_file
        self.original_state = self.fetch_state()
        self.current_state = self.original_state
        self.current_servers = self.parse_original_state()

        # If we're not root, or otherwise privileged, then
        # we probably aren't going to be able to change anything in the
        # real config.  We might not be asked to, so this isn't necessarily
        # fatal, but we make note of it.
        #
        if os.geteuid() != 0:
            self.logger.warn('Not EUID root; this might cause problems')

    def parse_original_state(self):
        """
        Parse the original state (for linux, just the resolv.conf)
        into the list of nameservers.

        If there are any other entries in the resolv.conf, such
        as aliases or networks, we ignore them.
        """

        lines = [line.strip()
                for line in re.split('\n', self.original_state)]

        servers = [re.sub('nameserver', '', line).strip()
                for line in lines if line.startswith('nameserver')]

        return servers

    def fetch_state(self):
        """ See DnsManager.fetch_state """

        # This is particularly simple for linux, which seems to keep
        # all of its state in self.config_file.

        try:
            return open(self.config_file, 'r').read()
        except IOError, exc:
            self.logger.warn("failed to read [%s]: %s" %
                    (self.config_file, str(exc)))
            return ''

    def restore_state(self):
        """ See DnsManager.restore_state """

        try:
            fout = open(self.config_file, 'w+')
            fout.write(self.original_state)
            fout.close()
        except IOError, exc:
            self.logger.warn("failed to restore [%s]: %s" %
                    (self.config_file, str(exc)))
            return False

        # Update the servers. 
        #
        self.current_servers = self.parse_original_state()

        return True

    def get_current_servers(self):
        """ See DnsManager.get_current_servers """

        return self.current_servers[:]

    def clear_servers(self):
        """ See DnsManager.clear_servers """

        self.current_servers = []

        try:
            fout = open(self.config_file, 'w+')
            fout.write('')
            fout.close()
            return True
        except IOError, exc:
            self.logger.warn("failed to clear [%s]: %s" %
                    (self.config_file, str(exc)))
            return False

    def add_servers(self, server_list):
        """ See DnsManager.add_servers """

        # Note we don't sanity-check the elements of server_list
        # (or even whether server_list is iterable, etc)

        # Nothing to do: do nothing.
        if not server_list:
            return True

        try:
            fout = open(self.config_file, 'a+')
        except IOError, exc:
            self.logger.warn("failed to add servers to [%s]: %s" %
                    (self.config_file, str(exc)))
            return False

        for server in server_list:
            if server in self.current_servers:
                pass
            else:
                fout.write('nameserver %s\n' % (server,))
                self.current_servers.append(server)

        fout.close()
        return True


class DnsManagerWindows(DnsManager):
    """
    Eventual home of an implementation of the DnsManager
    interface for Windows.

    """

    def __init__(self):
        """
        """

        DnsManager.__init__(self)

        self.logger = logging.getLogger('cb.vpn')
        self.logger.debug('Initializing Windows DNS manager')

    def fetch_state(self):
        """
	Does nothing yet
	
	See DnsManager.fetch_state
	"""

	return ''

    def restore_state(self):
        """
	Does nothing yet.
	
	See DnsManager.restore_state
	"""

        return True

    def get_current_servers(self):
        """
	Does nothing yet.
	
	See DnsManager.get_current_servers
	"""

        return list([])

    def clear_servers(self):
        """
	Does nothing yet.
	
	See DnsManager.clear_servers
	"""

	return True

    def add_servers(self, server_list):
        """
	Does nothing yet.
	
	See DnsManager.add_servers
	"""

	return True


if __name__ == '__main__':

    def testme():
        """ Simple, incomplete test driver. """

        dns = DnsManagerLinux(config_file='./test-resolv.conf')
        # dns = DnsManagerLinux()

        print dns.current_servers

        print dns.get_current_servers()

        dns.add_servers(['8.8.8.8'])
        dns.add_servers(['1.2.3.8'])

        dns.restore_state()

        return 0

    exit(testme())

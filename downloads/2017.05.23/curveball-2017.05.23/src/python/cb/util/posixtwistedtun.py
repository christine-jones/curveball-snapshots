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

import errno
import fcntl
import logging
import os
import struct

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from zope.interface import implements

import cb.util.platform

if cb.util.platform.PLATFORM in ['android', 'darwin']:
    TUN_PATH = '/dev/tun'
else:
    TUN_PATH = '/dev/net/tun'

class LinuxTwistedTUN:
    """
    Implements a TwistedTUN for Linux-based platforms (Ubuntu, Android)
    """

    implements(IReadDescriptor)
    def __init__(self, callback, interface='tun0', ip_addr=None,
                 netmask='255.255.255.0',
                 logname='cb.tcphijack',
                 tunowner=1000):
        """ Constructor

        Creates the TUN device, sets the file descriptor, and registers
        itself with the Twisted reactor

        Parameters:
            callback: The callback function (that takes a single pkt argument)
                to call when a packet has been read
            interface: The name of the TUN interface to create.  If
                specified as '', then the system will find an available
                device or create a new device.
            ip_addr: The IP address to give the interface
            netmask: The netmask to configure for the interface
            logname: The name of the logger for this instance
            tunowner: The uid of the tun owner (?)
        """
        self.interface = interface

        (self.fdesc, self.iface) = self.open_tun(tunowner,
                interface, ip_addr, netmask)
        self.callback = callback

        self.log = logging.getLogger(logname)

        reactor.addReader(self)

    def open_tun(self, tun_owner, interface, inetaddr, netmask):
        """
        Open a tun device.  Return the fdesc and the name as a tuple.

        This assumes that the platform is Linux-based ('linux2' or 'android')
        """

        tunsetiff   = 0x400454ca
        tunsetowner = tunsetiff + 2
        iff_tun     = 0x0001
        iff_no_pi = 0x1000
        tun = os.open(TUN_PATH, os.O_RDWR | os.O_NONBLOCK)

        params = buffer(struct.pack("16sH", interface, iff_tun | iff_no_pi))

        taken_params = fcntl.ioctl(tun, tunsetiff, params)
        ifacename = taken_params[:16].strip("\x00")

        fcntl.ioctl(tun, tunsetowner, tun_owner)

        if not inetaddr is None:
            os.system('ifconfig %s inet %s netmask %s' %
                    (ifacename, inetaddr, netmask))

        return (tun, ifacename)

    def iface_name(self):
        return self.iface

    def fileno(self):
        return self.fdesc

    def logPrefix(self):
        return 'TwistedTUN %s' % self.iface_name()

    def doRead(self):

        # Read a few packets, less stress on poll
        for _ in range(15):
            try:
                buff = os.read(self.fdesc, 8192)
            except os.error, exc:
                if exc[0] == errno.EAGAIN:
                    return
                else:
                    raise
            self.callback(buff)

    def connectionLost(self, reason):
        pass

    def __del__(self):
        """ If the object dies, remove the reader for the reactor
        and clean up the fdesc if it's still open """
        reactor.removeReader(self)
        if hasattr(self, 'fdesc') and self.fdesc >= 0:
            try:
                os.close(self.fdesc)
            except OSError:
                pass

    def write(self, data):
        return os.write(self.fdesc, data)


class DarwinTwistedTUN(LinuxTwistedTUN):
    """
    Implements a TwistedTUN for Darwin-based platforms (Mac OS X)
    """
    implements(IReadDescriptor)

    def __init__(self, callback, interface='tun0', ip_addr=None,
                 netmask='255.255.255.0',
                 logname='cb.tcphijack',
                 tunowner=1000):
        LinuxTwistedTUN.__init__(self, callback, interface, ip_addr,
                netmask, logname, tunowner)

    def open_tun(self, tun_owner, interface, inetaddr, netmask):
        """
        Open a TUN on Darwin
        """

        max_tun = 16
        tun_num = 0 # to convince pylint that this is always defined...

        # make sure that the kernel module is loaded
        # TODO: check that this succeeds!
        #
        os.system('sudo /sbin/kextload /opt/local/Library/Extensions/tun.kext')

        # poll for a free tun.  There doesn't seem to be any other way.
        #
        for tun_num in range(0, max_tun):
            tun_name = '%s%d' % (TUN_PATH, tun_num)
            tun = None
            try:
                tun = os.open(tun_name, os.O_RDWR | os.O_NONBLOCK)
                break
            except BaseException, exc:
                print str(exc)

        if tun == None:
            print 'Failed to find a TUN'
            return None

        tun_iface = 'tun%d' % tun_num

        print 'found tun [%s]' % tun_iface

        if not inetaddr is None:
            os.system('ifconfig %s inet %s %s netmask %s' %
                    (tun_iface, inetaddr, inetaddr, netmask))

        return (tun, tun_iface)

    # The TUN on Darwin is blocking, even if we set it to be non-blocking.
    # Therefore we define completely different methods for reading packets
    # depending on whether the TUN will tell us when we're out of packets
    # or having to read one packet per poll.  (there are known issues with
    # tuntaposx and polling)  We do this at load time rather than run time
    # to keep the platform check out of the innermost loop.
    #
    def doRead(self):
        buff = os.read(self.fdesc, 8192)
        self.callback(buff)


#if __name__ == '__main__':
#    import unittest
#    import dpkt
#
#    class TwistedTunTest(unittest.TestCase):
#        def cb(rawpkt):
#            pkt =  dpkt.ip.IP(rawpkt)
#            print dpkt_util.dpkt_to_str(pkt)
#        def test_init:
#            tun = TwistedTUN(cb, 'tun5', '10.6.0.10')
#            reactor.run()
#
#    unittest.main()

if __name__ == '__main__':
    import cb.util.dpkt_util

    def main():
        def callback(rawpkt):
            print 'bingo'
            print ''.join(['%.3d-' % ord(x) for x in rawpkt])

        tun = LinuxTwistedTUN(callback, 'tun0', '10.6.0.10')
        reactor.run()

    main()

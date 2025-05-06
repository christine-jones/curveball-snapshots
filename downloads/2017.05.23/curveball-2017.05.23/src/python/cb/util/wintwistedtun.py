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

import _winreg as reg
import msvcrt
import win32file
import win32event
import winerror
import os
import logging
import struct
import errno
import socket
from threading import Thread
from multiprocessing import Process
import logging
import time

import twisted.internet.endpoints as endpoints
from twisted.internet.protocol import Factory, Protocol
from zope.interface import implements
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor


def get_device_guid():
    adapter_key = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, adapter_key) as adapters:
        try:
            for i in xrange(10000):
                key_name = reg.EnumKey(adapters, i)
                with reg.OpenKey(adapters, key_name) as adapter:
                    try:
                        component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                        if component_id.startswith('tap'):
                            return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                    except WindowsError, err:
                        pass
        except WindowsError, err:
            pass
        
def get_interface_from_guid(guid):
    reg_key = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\%s\Connection' % guid
    name = None
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, reg_key) as adapter:
        try:
            name = reg.QueryValueEx(adapter, 'Name')[0]
        except WindowsError, err:
            pass
    return name
        

def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method;

def TAP_CONTROL_CODE(request, method):
    return CTL_CODE(34, request, method, 0)

TAP_IOCTL_CONFIG_POINT_TO_POINT = TAP_CONTROL_CODE(5, 0)
TAP_IOCTL_SET_MEDIA_STATUS = TAP_CONTROL_CODE(6, 0)
TAP_IOCTL_CONFIG_TUN = TAP_CONTROL_CODE(10, 0)


TUN_S_PORT=5721


def read_win_tun_sync(handle, tun_s_port):

    # Connect to the server
    try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('127.0.0.1', tun_s_port))
    except BaseException, exc:
	print str(exc)
	return

    while True:
        _, p = win32file.ReadFile(handle, 4096)
	if len(p):
	    s.send(p)
	else:
	    break


def read_win_tun(handle, tun_s_port):

    # Connect to the server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', tun_s_port))
    except BaseException, exc:
        print str(exc)
        return

    while True:
        overlap = win32file.OVERLAPPED()
        overlap.hEvent = win32event.CreateEvent(None, 1, 0, None)
        read_buf = win32file.AllocateReadBuffer(4096)
        read_bytes = ''
    
        rc, buf = win32file.ReadFile(handle, win32file.AllocateReadBuffer(4096), overlap)
        win32event.WaitForSingleObject(overlap.hEvent, win32event.INFINITE)
        read_cnt = win32file.GetOverlappedResult(handle, overlap, 0)

        #read = str(buf)
        #print "Sending %d bytes" % read_cnt
        s.send(buf[:read_cnt])

    
#        status, p = win32file.ReadFile(handle, read_buf, overlap)
#
#        if status == 0:
#            read_bytes = p
#            # print "GOT SOMETHING (immediate)"
#        elif status == winerror.ERROR_IO_PENDING:
#            win32event.WaitForSingleObject(overlap.hEvent,
#                win32event.INFINITE)
#            read_cnt = win32file.GetOverlappedResult(handle, overlap, 0)
#            read_bytes = str(read_buf[:read_cnt])
#                # print "GOT SOMETHING (after wait)"
#        elif status == winerror.ERROR_MORE_DATA:
#            print "UNEXPECTED: data overrun"
#
#        import binascii
#        print "Sending %d bytes: %s" % (len(read_bytes), binascii.hexlify(read_bytes))        
#        s.send(read_bytes)


class TunReadProtocol(Protocol):
    """
    Connects to SOCKS
    """

    def __init__(self):

        self.log = logging.getLogger('cb.wintun')
        self.log.debug('%s created new TunReadProtocol')

        self.cb = None
        self.pkt_buf = ''
 
    def dataReceived(self, data):
        """
        When the service socket is readable, read a small amount of data
        from it, wrap it up in a CCPMessage, and pass it to the client
        sock for this connection.

        It's not an error if the read is incomplete, and handle_close will
        clean up implicitly if there is a zero-length recv.
        """

        # Turn the streamed packets into actual packets
        self.pkt_buf += data
        
        while True:
            if len(self.pkt_buf) < 20:
                break
            #import binascii
            
            #print "self.pkt_buf[2:4] = %s" % binascii.hexlify(self.pkt_buf[2:4])
            plen = struct.unpack('!H', self.pkt_buf[2:4])[0]
            #print "len = %d" % plen
            #print 'Packet len = %d -- %s' % (plen, binascii.hexlify(self.pkt_buf[:20]))
            
            
            if len(self.pkt_buf) < plen:
                break
            
            pkt = self.pkt_buf[:plen]
            self.pkt_buf = self.pkt_buf[plen:]
            self.cb(pkt)
            
    def connectionMade(self):
        self.cb = self.factory.cb
        self.log.debug("TunReadProtocol Connected to Tun Reader")
        
def net(ip, mask):
    ips = ip.split('.')
    masks = mask.split('.')
    net = []
    for i in range(4):
        net.append(str(int(ips[i]) & int(masks[i])))
    return '.'.join(net)

class WinTwistedTUN:
    def __init__(self, callback, interface='tun0', ip_addr=None, 
                 netmask='255.255.255.0',
                 logname='cb.tcphijack',
                 tunowner=None):
        """ Constructor
        
        Creates the TUN device, sets the file descriptor, and registers
        itself with the Twisted reactor
        
        Parameters:
            callback: The callback function (that takes a single pkt argument)
                to call when a packet has been read
            ip: The IP address to give the interface
            netmask: The netmask to configure for the interface
            logname: The name of the logger for this instance
        """

        self.log = logging.getLogger('cb.util.twistedtun')

        guid = get_device_guid()
        interface = get_interface_from_guid(guid)
        self.log.debug("TUN Interface = %s" % interface)
        print interface
        
        handle = win32file.CreateFile(r'\\.\Global\%s.tap' % guid,
                                      win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                      win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                      None, win32file.OPEN_EXISTING,
                                      win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                                      win32file.FILE_SHARE_READ)
        win32file.DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS, '\x01\x00\x00\x00', None)

        network = net(ip_addr, netmask)
        
        args = ''
        args += socket.inet_aton(ip_addr)
        args += socket.inet_aton(network)
        args += socket.inet_aton(netmask)
        
        win32file.DeviceIoControl(handle, TAP_IOCTL_CONFIG_TUN, args, None)

        self.handle = handle

        # Okay we have a Tun device up, now we need to set the IP
        
        os.popen("netsh int ip set address \"%s\" static %s %s" % (interface, ip_addr, netmask))
        
        # Now we need to create the socket to communicate between the Tun reading thread
        # and Twisted
        
        # First the socket listener
        tunreadfactory = Factory()
        tunreadfactory.protocol = TunReadProtocol
        tunreadfactory.cb = callback
        endpoint = endpoints.TCP4ServerEndpoint(reactor, TUN_S_PORT)
        endpoint.listen(tunreadfactory)

        # Now the producer that reads TUN and writes to the socket
        t = Thread(target=read_win_tun, args=(handle, TUN_S_PORT))
        # t = Process(target=read_win_tun, args=(guid, TUN_S_PORT))
        t.daemon = True
        t.start()
        
    def write(self, data):
        overlap = win32file.OVERLAPPED()
        overlap.hEvent = win32event.CreateEvent(None, 0, 0, None)
        
        err, n = win32file.WriteFile(self.handle, data, overlap)
        if err:
            win32event.WaitForSingleObject(overlap.hEvent, win32event.INFINITE)


if __name__ == '__main__':
    def cb(pkt):
        print "got a packet! src = %s" % socket.inet_ntoa(pkt[12:16])
        
    tun = WinTwistedTUN(cb, ip_addr='192.168.99.88',  netmask='255.255.255.0')
    
    reactor.run()

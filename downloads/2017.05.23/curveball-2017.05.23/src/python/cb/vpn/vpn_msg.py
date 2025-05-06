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
Helper classes/methods for VPN-over-Curveball
"""

import logging
import re
import struct

# Imported for effect.
import cb.util.cblogging

# If _DEBUG is False, then we don't check much.  If _DEBUG is True,
# then we make an effort to validate inputs and results.
#
_DEBUG = False

# Performance will suffer if we create a logger for each message,
# or if we do all the checking for each message.  So we have module
# variables instead of instance variables for these.
#
_LOGGER = logging.getLogger('cb.vpn')

def set_debug(mode):
    """
    Set the debug mode (True or False).
    """

    global _DEBUG

    if mode:
        _DEBUG = True
    else:
        _DEBUG = False

def get_debug():
    """
    Return the current debug mode (True or False)
    """

    return (_DEBUG)


# Msg format:
#   version (1 byte: 1)
#   msg_type (1 byte: 1 = open, 2 = close, 3 = info, 10 = forward)
#   msg_text_len (2 bytes)
#   msg_text (0..65535 bytes) -- must fit in 16 bits!
#
VERSION = 1

OPEN_SESSION = 1
CLOSE_SESSION = 2
SESSION_INFO = 3
FORWARD_PKT = 10

MAX_MSG_LEN = 65535

class VpnMsgWrapper(object):
    """
    Very simple message wrapping, primarily for debugging

    Should be folded into CCP, eventually.  That will be messy as long as CDP
    has to support general sockets as well.
    """

    HEADER_FMT = '!BBH'

    def __init__(self, msg_type, msg_text):

        # if msg_text is anything "untrue", substitute ''.
        #
        if not msg_text:
            msg_text = ''

        if _DEBUG:
            if not msg_type in [
                    OPEN_SESSION, CLOSE_SESSION, SESSION_INFO, FORWARD_PKT
                    ]:
                _LOGGER.warn("Bad msg_type: %s[%s]" %
                        (str(type(msg_type)), str(msg_type)))
                raise ValueError("Bad msg_type: %s[%s]" %
                        (str(type(msg_type)), str(msg_type)))

            if type(msg_text) != str:
                _LOGGER.warn("Bad msg_text type: %s" %
                        (str(type(msg_text)),))
                raise TypeError("Bad msg_text type: %s" %
                        (str(type(msg_text)),))

            if len(msg_text) > MAX_MSG_LEN:
                _LOGGER.warn("msg_text too long (%d bytes)" %
                        (len(msg_text),))
                raise ValueError("msg_text too long (%d bytes)" %
                        (len(msg_text),))

        self._version = VERSION
        self._msg_type = msg_type
        self._msg_text_len = len(msg_text)
        self._msg_text = msg_text

    def get_version(self):
        """ accessor for version """
        return self._version

    def get_msg_type(self):
        """ accessor for msg_type """
        return self._msg_type

    def get_msg_text_len(self):
        """ accessor for msg_text_len """
        return self._msg_text_len

    def get_msg_text(self):
        """ accessor for msg_text """
        return self._msg_text

    def parse_info(self):
        """
        Return a tuple of the (tun_ip, tun_netmask, dns_params)
        from the given info message.

        This is very dependant on the format of the info message;
        see the info_msg method below.
        """

        fmt = "tun_ip=(\S+)/tun_netmask=(\S+)/dns=(\S+)"
        print self._msg_text
        match = re.match(fmt, self._msg_text)

        if not match:
            _LOGGER.warn("Failed to parse info msg")
            return None
        else:
            (tun_ip, tun_netmask, dns_servers) = match.group(1, 2, 3)
            return (tun_ip, tun_netmask, dns_servers.split(','))

    @staticmethod
    def open_msg():
        """ Convenience method to create an 'open' msg. """
        return VpnMsgWrapper(OPEN_SESSION, '')

    @staticmethod
    def close_msg():
        """ Convenience method to create a 'close' msg. """
        return VpnMsgWrapper(CLOSE_SESSION, '')

    @staticmethod
    def info_msg(tun_ip, tun_netmask, dns_addr):
        """ Convenience method to create a 'info' msg. """

        text = 'tun_ip=%s/tun_netmask=%s/dns=%s' % (
                tun_ip, tun_netmask, dns_addr)
        return VpnMsgWrapper(SESSION_INFO, text)

    @staticmethod
    def pkt_msg(pkt):
        """ Convenience method to create a 'forward pkt' msg. """
        return VpnMsgWrapper(FORWARD_PKT, pkt)

    def pack(self):
        """ pack an instance into wire format """
        header = struct.pack(VpnMsgWrapper.HEADER_FMT,
                self._version, self._msg_type, self._msg_text_len)

        if self._msg_text_len > 0:
            return header + self._msg_text
        else:
            return header

    def __str__(self):
        """ Human-readable string representing the header """

        return "VpnMsgWrapper: ver %d type %d text_len %d" % (
                self.get_version(), self.get_msg_type(),
                self.get_msg_text_len())

    @staticmethod
    def recv_from_buffer(recv_buffer):
        """
        Given a buffer of recv'd messages, parse out as many as possible.
        Return a tuple (msgs, remaining_buffer) where msgs is a list of
        the VpnMsgWrappers parsed from recv_buffer, and remaining_buffer
        the leftover, unconsumed tail of recv_buffer (if any).

        If the parse fails, assume that the channel is corrupted, and
        return None.  If this happens the channel should be abandoned.
        """

        # See ccp.py.
        # Seems silly to reproduce so much code

        header_len = struct.calcsize(VpnMsgWrapper.HEADER_FMT)

        msgs = []

        while True:
            if len(recv_buffer) < header_len:
                return (msgs, recv_buffer)

            header = recv_buffer[:header_len]

            (version, msg_type, msg_text_len) = struct.unpack(
                    VpnMsgWrapper.HEADER_FMT, header)

            if version != VERSION:
                _LOGGER.warn("Bad msg VERSION (%d)" % (version,))
                return None

            tot_msg_len = header_len + msg_text_len

            if len(recv_buffer) < tot_msg_len:
                return (msgs, recv_buffer)

            if msg_text_len == 0:
                msg_text = ''
            else:
                msg_text = recv_buffer[header_len:tot_msg_len]

            recv_buffer = recv_buffer[tot_msg_len:]

            try:
                msgs.append(VpnMsgWrapper(msg_type, msg_text))
            except BaseException, _exc:
                _LOGGER.warn("Buffer cannot be parsed")
                return None


# test rig.
if __name__ == '__main__':

    set_debug(10)
    print get_debug()

    set_debug(0)
    print get_debug()


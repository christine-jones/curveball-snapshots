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

import socket
import struct
import sys

class RemoraMessage(object):

    # current protocol version
    PROTOCOL_VERSION = 1

    # valid message types
    MSG_CURVEBALL_CONNECTION_REQUEST  = 1
    MSG_CURVEBALL_CONNECTION_RESPONSE = 2

    # on-the-wire format
    #    1B  protocol_version
    #    1B  message_type
    #    2B  data_length (bytes, not including the header)
    #        data (if data_length is > 0)
    #
    HEADER_FORMAT = '!BBH'
    HEADER_LENGTH = struct.calcsize(HEADER_FORMAT)

    MSG2STR = {
            MSG_CURVEBALL_CONNECTION_REQUEST  : 'req',
            MSG_CURVEBALL_CONNECTION_RESPONSE : 'resp'
        }

    def __init__(self, msg_type, data=None):

        # check parameters for goodness
        if type(msg_type) != int:
            raise TypeError('illegal msg_type (%s)' % str(type(msg_type)))

        if not msg_type in RemoraMessage.MSG2STR:
            raise ValueError('illegal msg_type (%d)' % msg_type)

        if not data:
            data = ''

        self.protocol_version = RemoraMessage.PROTOCOL_VERSION
        self.msg_type = msg_type
        self.data = data

    def pack(self, data=None):
        """
        convert to wire format
        """

        if data:
            self.data = data

        header = struct.pack(RemoraMessage.HEADER_FORMAT,
                self.protocol_version, self.msg_type, len(self.data))

        return header + self.data

    @staticmethod
    def recv_from_buffer(data_buffer):
        """
        extracts a RemoraMessage from a buffer
        """

        header_len = RemoraMessage.HEADER_LENGTH
        header_fmt = RemoraMessage.HEADER_FORMAT

        if len(data_buffer) < header_len:
            return (None, data_buffer)

        header_buf = str(data_buffer[:header_len])

        (protocol_version, msg_type, data_length) = struct.unpack(
                header_fmt, header_buf)

        total_len = header_len + data_length

        if len(data_buffer) < total_len:
            return (None, data_buffer)

        data = data_buffer[header_len:total_len]
        tmp_buf = data_buffer[total_len:]

        if protocol_version != RemoraMessage.PROTOCOL_VERSION:
            raise ValueError('invalid protocol version (%u)' %
                    len(protocol_version))
            return (None, data_buffer)

        msg = RemoraMessage(msg_type, data)
        msg.protocol_version = protocol_version
        return (msg, tmp_buf)

    def __str__(self):

        if self.msg_type in RemoraMessage.MSG2STR:
            msg_type = RemoraMessage.MSG2STR[self.msg_type]
        else:
            msg_type = '??(%d)' % self.msg_type

        text  = 'RemoraMessage:'
        text += ' v %u' % self.protocol_version
        text += ' msg_type %u' % self.msg_type
        text += ' len %u' % len(self.data)

        return text


class RemoraMessageRequest(RemoraMessage):

    # on-the-wire format
    #    header
    #    no data (data_length is 0)

    def __init__(self):

        try:
            super(RemoraMessageRequest, self).__init__(
                    RemoraMessage.MSG_CURVEBALL_CONNECTION_REQUEST)
        except TypeError:
            raise
        except ValueError:
            raise

    def pack(self, data=None):
        """
        convert to wire format
        """

        if data != None:
            raise ValueError('data will be ignored')
            return

        return super(RemoraMessageRequest, self).pack()

    def unpack(self):

        if len(self.data) != 0:
            raise ValueError('invalid data length (%u)' % len(self.data))
            return

    def __str__(self):

        return super(RemoraMessageRequest, self).__str__()


class RemoraMessageResponse(RemoraMessage):

    # on-the-wire format
    #        header
    #    4B  addr
    #    2B  port
    #    2B  padding
    #    2B  host_length
    #    2B  url_length
    #        host (variable length)
    #        url (variable length)
    RESPONSE_HFORMAT = '!4sHHHH'
    RESPONSE_HLENGTH = struct.calcsize(RESPONSE_HFORMAT)

    def __init__(self, addr, port, host=None, url=None):

        if not host:
            host = addr

        if not url:
            url = '/'

        try:
            super(RemoraMessageResponse, self).__init__(
                    RemoraMessage.MSG_CURVEBALL_CONNECTION_RESPONSE)
        except TypeError:
            raise
        except  ValueError:
            raise

        if type(port) != int:
            raise TypeError('illegal port type (%s)' % str(type(port)))

        if port < 0 or port > 65535:
            raise ValueError('invalid port value (%u)' % port)

        # make sure that it's an address, not a hostname
        # (if it's already an address, gethostbyname will just return it)
        #
        self.addr = socket.gethostbyname(addr)
        self.port = port
        self.host = host
        self.url  = url

    def pack(self, data=None):
        """
        convert to wire format
        """

        if data != None:
            raise ValueError('data will be ignored')
            return

        msg = struct.pack(RemoraMessageResponse.RESPONSE_HFORMAT,
                socket.inet_aton(self.addr), self.port, 0,
                len(self.host), len(self.url))

        msg += (self.host + self.url)

        return super(RemoraMessageResponse, self).pack(msg)

    def unpack(self):

        if len(self.data) < RemoraMessageResponse.RESPONSE_HLENGTH:
            raise ValueError('insufficient data buffer for response message')
            return

        header_buf = self.data[:RemoraMessageResponse.RESPONSE_HLENGTH]
        (addr, port, padding, host_length, url_length) = struct.unpack(
                RemoraMessageResponse.RESPONSE_HFORMAT, header_buf)

        if len(self.data) < host_length + url_length:
            raise ValueError('insufficient data buffer for host and url')
            return

        if port < 0 or port > 65535:
            raise ValueError('invalid port value (%u)' % port)
            return

        end_host = (RemoraMessageResponse.RESPONSE_HLENGTH + host_length)
        end_url  = end_host + url_length

        self.addr = socket.inet_ntoa(addr)
        self.port = port
        self.host = self.data[RemoraMessageResponse.RESPONSE_HLENGTH:end_host]
        self.url  = self.data[end_host:end_url]

    def __str__(self):

        text = super(RemoraMessageResponse, self).__str__()
        text += '\n'
        text += '    Response:'
        text += ' addr %s' % self.addr
        text += ' port %s' % self.port
        text += ' host %u %s' % (len(self.host), self.host)
        text += ' url %u %s' % (len(self.url), self.url)

        return text

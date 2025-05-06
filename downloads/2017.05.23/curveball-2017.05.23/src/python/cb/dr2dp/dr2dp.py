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
Implementation of the base object for DR2DP messages.
"""

import socket
import struct
import sys

import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))
# FIXME -- replace DEBUG and debug(...) with self.log.debug(...)
def debug(msg):
    print >> sys.stderr, 'DR2DP: %s' % msg

# FIXME -- replace log_warn with self.log.warn
def log_warn(msg):
    print >> sys.stderr, 'DR2DP_DP(warning): %s' % msg

# FIXME -- replace log_info with self.log.info
def log_info(msg):
    print >> sys.stderr, 'DR2DP_DP(info): %s' % msg

class DR2DPMessage1(object):
    """
    Base object for DR2DP messages
    """

    # current protocol version
    PROTOCOL_VERSION = 2

    # valid message types
    MESSAGE_TYPE_REQUEST = 1
    MESSAGE_TYPE_RESPONSE = 2

    # valid operation types
    OP_TYPE_PING = 1
    OP_TYPE_FORWARD_IP = 2
    OP_TYPE_SENTINEL_FILTER = 3
    OP_TYPE_REDIRECT_FLOW = 4
    OP_TYPE_REMOVE_FLOW = 5
    OP_TYPE_REASSIGN_FLOW = 6
    OP_TYPE_TLS_FLOW_ESTABLISHED = 7
    OP_TYPE_ICMP = 8
    OP_TYPE_DH_BLACKLIST = 10

    # valid response codes
    RESPONSE_SUCCESS = 0

    # The on-the-wire format:
    #     1B  protocol_version
    #     1B  session_type
    #     1B  msg_type
    #     1B  op_type
    #     4B  response_code (success or error code)
    #     8B  xid (exchange identifier)
    #     8B  data length (bytes, not including the header)
    #         data (if data length is > 0)
    #
    HEADER_FORMAT = '!BBBBLQQ'
    HEADER_LENGTH = struct.calcsize(HEADER_FORMAT)

    TYPE2STR = {
            MESSAGE_TYPE_REQUEST : 'req',
            MESSAGE_TYPE_RESPONSE : 'resp'
        }

    OP2STR = {
            OP_TYPE_PING : 'ping',
            OP_TYPE_FORWARD_IP : 'forward',
            OP_TYPE_SENTINEL_FILTER : 'filter',
            OP_TYPE_REDIRECT_FLOW : 'redirect',
            OP_TYPE_REMOVE_FLOW : 'remove',
            OP_TYPE_REASSIGN_FLOW : 'reassign',
            OP_TYPE_TLS_FLOW_ESTABLISHED : 'tls',
            OP_TYPE_ICMP : 'icmp',
            OP_TYPE_DH_BLACKLIST : 'blacklist'
        }

    def validate(self):
        """
        Check that the xid makes sense

        This is just an incomplete stub.
        """

        DEBUG and debug("validate; message type = %s"
                        % DR2DPMessage1.TYPE2STR[self.msg_type])

        if ((self.msg_type == DR2DPMessage1.MESSAGE_TYPE_RESPONSE) and
                (not self.xid)):
            # Whoops!  responses need XIDs
            pass
        elif ((self.msg_type == DR2DPMessage1.MESSAGE_TYPE_REQUEST) and
                self.xid):
            # Whoops!  requests choose their own XIDs
            pass
        else:
            # Whoops!  unknown msg_type.
            pass

        return True

    def __init__(self, msg_type, op_type, data=None):

        # Check the parameters for goodness
        if type(msg_type) != int:
            raise TypeError('illegal msg_type type (%s)' % (
                (str(type(msg_type))),))

        if type(op_type) != int:
            raise TypeError('illegal op_type type (%s)' % (
                (str(type(op_type))),))

        if not msg_type in DR2DPMessage1.TYPE2STR:
            raise ValueError('illegal msg_type (%d)' % (msg_type,))

        if not op_type in DR2DPMessage1.OP2STR:
            raise ValueError('illegal op_type (%d)' % (op_type,))

        DEBUG and debug("init (msg, op): (%s, %s)"
                        % (DR2DPMessage1.TYPE2STR[msg_type],
                           DR2DPMessage1.OP2STR[op_type]))

        if not data:
            data = ''

        self.msg_type = msg_type
        self.op_type = op_type
        self.data = data

        # This constructor sets the protocol_version, session_type,
        # response_code, and xid to default values; constructors for
        # subclasses override these
        #
        self.protocol_version = DR2DPMessage1.PROTOCOL_VERSION
        self.session_type = 0
        self.response_code = DR2DPMessage1.RESPONSE_SUCCESS
        self.xid = 0

    def pack(self, data=None):
        """
        Convert to wire format
        """

        if data:
            self.data = data

        header = struct.pack(DR2DPMessage1.HEADER_FORMAT,
                self.protocol_version, self.session_type,
                self.msg_type, self.op_type, self.response_code,
                self.xid, len(self.data))

        return header + self.data

    @staticmethod
    def recv_from_buffer(data_buffer):
        """
        Tries to extract a message from a buffer.

        Return (msg, buffer-minus-msg) if the head of the buffer contains
        msg, where buffer-minus-msg is the original buffer with the bytes
        representing the msg scooped out.

        Return (None, buffer) if there isn't a complete message yet.

        TODO: gets really, really confused if the buffer contains garbage.
        """

        header_len = DR2DPMessage1.HEADER_LENGTH
        header_fmt = DR2DPMessage1.HEADER_FORMAT

        # if there's not even enough data for even a header, then we can give
        # up immediately
        #
        if len(data_buffer) < header_len:
            return (None, data_buffer)

        header_buf = str(data_buffer[:header_len])

        (protocol_version, session_type, msg_type, op_type, response_code, xid,
                data_len) = struct.unpack(header_fmt, header_buf)

        # TODO: we could check that the header values are self-consistent and
        # make sense.

        total_len = header_len + data_len

        # If we got the header, but not all of the data has arrived, then
        # give up
        #
        if len(data_buffer) < total_len:
            DEBUG and debug("recv_from_buffer: data buffer (%d bytes) shorter than expected (%d bytes: %d + %d)"
                            % (len(data_buffer), total_len,
                               header_len, data_len))
            return (None, data_buffer)

        # TODO - this slicing might kill our performace when the
        # messages are large.
        #
        data_buf = data_buffer[header_len:total_len]
        tmp_buf = data_buffer[total_len:]

        msg =  DR2DPMessage1(msg_type, op_type, data_buf)

        # Fill in the fields that the low-level constructor ignores.
        #
        msg.protocol_version = protocol_version
        msg.session_type = session_type
        msg.response_code = response_code
        msg.xid = xid
        DEBUG and debug("recv_from_buffer: returning %d bytes"
                        % len(tmp_buf))

        return (msg, tmp_buf)

    @staticmethod
    def recv(sock):
        """
        Receive a DR2DPMessage in wire format, and reconstitute it into a
        DR2DPMessage instance.

        ASSUMES THAT THE SOCK IS BLOCKING.  DO NOT USE WITH ASYNCORE.

        Unlike __init__, which builds just the base class, this method
        initializes all the basic fields.  It is the responsibility of a
        superclass to ensure that the values make sense.
        """

        DEBUG and debug("recv")

        header = ''
        while len(header) < DR2DPMessage1.HEADER_LENGTH:
            header += sock.recv(DR2DPMessage1.HEADER_LENGTH - len(header))

        (protocol_version, session_type, msg_type, op_type, response_code, xid,
                data_len) = struct.unpack(DR2DPMessage1.HEADER_FORMAT, header)

        # TODO: we could check that the header values are self-consistent and
        # make sense.

        # TODO - this is not an efficient way to deal with large reads.
        # It might be catastrophically inefficient for reads of larger than
        # 1MB.
        #
        data = ''
        while len(data) < data_len:
            data += sock.recv(data_len - len(data))

        msg =  DR2DPMessage1(msg_type, op_type, data)

        # Fill in the fields that the low-level constructor ignores.
        #
        msg.protocol_version = protocol_version
        msg.session_type = session_type
        msg.response_code = response_code
        msg.xid = xid

        DEBUG and debug("recv: returning msg %s" % __str__(msg))


        return msg

    def __str__(self):
        """
        Create a human-readable string describing the msg header.

        (the string will not contain a representation of the msg data itself)
        """

        # Be prepared for garbage messages; don't assume that everything we get
        # can be converted to something meaningful
        #
        if self.msg_type in DR2DPMessage1.TYPE2STR:
            mtype = DR2DPMessage1.TYPE2STR[self.msg_type]
        else:
            mtype = '??(%d)' % self.msg_type

        if self.op_type in DR2DPMessage1.OP2STR:
            otype = DR2DPMessage1.OP2STR[self.op_type]
        else:
            otype = '??(%d)' % self.op_type

        # This isn't efficient, but it makes it easier to mess with the
        # format while we're still debugging
        #
        text = 'DR2DPMessage1'
        text += ' v %u' % self.protocol_version
        text += ' sess %u' % self.session_type
        text += ' type %s' % mtype
        text += ' op %s' % otype
        text += ' resp %u' % self.response_code
        text += ' xid %x' % self.xid
        text += ' len %u' % len(self.data)

        return text

    def get_5tuple(self):
        if self.msg_type != DR2DPMessage1.OP_TYPE_FORWARD_IP:
            return ''

        fmt = '!B11sLL'
        (hdr_len, _, src_addr, dst_addr) = struct.unpack(fmt, self.data[:20])

        print '%x %s' % (src_addr, dst_addr)


class DR2DPMessageSentinelFilter(DR2DPMessage1):

    # The on-the-wire format:
    #    2B  hash_size
    #    2B  num_salts
    #        salt values (4B each)
    #
    FILTER_HFORMAT = '!HH'
    FILTER_HLENGTH = struct.calcsize(FILTER_HFORMAT)

    def __init__(self, hash_size, salts=None):

        try:
            super(DR2DPMessageSentinelFilter, self).__init__(
                DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_SENTINEL_FILTER)
        except TypeError, ValueError:
            raise

        if type(hash_size) != int:
            raise TypeError('illegal hash_size type (%s)' % (
                (str(type(hash_size))),))

        if salts and type(salts) != list:
            raise TypeError('illegal salts type (%s)' % (
                (str(type(salts))),))

        if hash_size < 0 or hash_size > 30:
            raise ValueError('illegal hash_size (%d)' % (hash_size,))

        if salts and len(salts) > 65535:
            raise ValueError('illegal salts length (%d)' % (len(salts),))

        self.hash_size = hash_size

        if not salts:
            salts = []
        self.salts = salts
        DEBUG and debug("RedirectFlow: %s" % str(self))

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageSentinelFilter.FILTER_HFORMAT +
                          len(self.salts) * 'L',
                          self.hash_size, len(self.salts), *self.salts)

        DEBUG and debug("SentinelMessage: pack %s" % str(self))

        return super(DR2DPMessageSentinelFilter, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) < DR2DPMessageSentinelFilter.FILTER_HLENGTH:
            raise ValueError('insufficient data buffer for sentinel message')
            return

        header_buf = self.data[:DR2DPMessageSentinelFilter.FILTER_HLENGTH]
        (hash_size, num_salts) = struct.unpack(
                                     DR2DPMessageSentinelFilter.FILTER_HFORMAT,
                                     header_buf)

        if hash_size < 0 or hash_size > 30:
            raise ValueError('invalid hash size (%d)' % (hash_size,))
        self.hash_size = hash_size

        salt_buffer = self.data[DR2DPMessageSentinelFilter.FILTER_HLENGTH:]
        if len(salt_buffer) != (num_salts * 4):
            raise ValueError('invalid buffer length (%d)' % (len(salt_buffer),))

        (self.salts) = struct.unpack('!' + num_salts * 'L', salt_buffer)

        DEBUG and debug("SentinelMessage: unpack %s" % str(self))

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageSentinelFilter, self).__str__()
        text += '\n'
        text += '    SentinelFilter'
        text += ' hash_size %u' % self.hash_size
        text += ' num_salts %u' % len(self.salts)

        for salt in self.salts:
            text += ' %u' % salt

        return text


class DR2DPMessageRedirectFlow(DR2DPMessage1):

    # The on-the-wire format:
    #    2B  flags
    #    1B  syn_option_length
    #    1B  ack_option_length
    #        syn_tcp_options (variable length)
    #        ack_tcp_options (variable length)
    #        sentinel_packets (variable length)
    #
    REDIRECT_HFORMAT = '!HBB'
    REDIRECT_HLENGTH = struct.calcsize(REDIRECT_HFORMAT)

    REDIRECT_FLAG_ACK = 0x0001

    def __init__(self, flags, syn_options, ack_options, sentinel_packets):

        try:
            super(DR2DPMessageRedirectFlow, self).__init__(
                DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_REDIRECT_FLOW)
        except TypeError, ValueError:
            raise

        if len(syn_options) > 40:
            raise ValueError('invalid syn_tcp_options length (%d)' %
                             (len(syn_options),))

        if len(ack_options) > 40:
            raise ValueError('invalid ack_tcp_options length (%d)' %
                             (len(ack_options),))

        self.flags = flags
        self.syn_tcp_options = syn_options
        self.ack_tcp_options = ack_options
        self.sentinel_packets = sentinel_packets
        DEBUG and debug("RedirectFlow: %s" % str(self))

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageRedirectFlow.REDIRECT_HFORMAT,
                          self.flags,
                          len(self.syn_tcp_options),
                          len(self.ack_tcp_options))
        msg += (self.syn_tcp_options +
                self.ack_tcp_options +
                self.sentinel_packets)

        return super(DR2DPMessageRedirectFlow, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) < DR2DPMessageRedirectFlow.REDIRECT_HLENGTH:
            raise ValueError('insufficient data buffer for redirect message')
            return

        header_buf = self.data[:DR2DPMessageRedirectFlow.REDIRECT_HLENGTH]
        (flags,
         syn_op_length,
         ack_op_length) = struct.unpack(
                              DR2DPMessageRedirectFlow.REDIRECT_HFORMAT,
                              header_buf)

        if len(self.data) < syn_op_length + ack_op_length:
            raise ValueError('insufficient data buffer for tcp options')
            return

        end_syn_options = (DR2DPMessageRedirectFlow.REDIRECT_HLENGTH +
                           syn_op_length)
        end_ack_options = end_syn_options + ack_op_length

        self.flags = flags
        self.syn_tcp_options = self.data[
            DR2DPMessageRedirectFlow.REDIRECT_HLENGTH:end_syn_options]
        self.ack_tcp_options = self.data[end_syn_options:end_ack_options]
        self.sentinel_packets = self.data[end_ack_options:]

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageRedirectFlow, self).__str__()
        text += '\n'
        text += '    RedirectFlow'
        text += ' flags %s' % hex(self.flags)
        text += ' len %u' % len(self.syn_tcp_options)
        text += ' %s' % self.syn_tcp_options
        text += ' len %u' % len(self.ack_tcp_options)
        text += ' %s' % self.ack_tcp_options
        text += ' %s' % self.sentinel_packets

        return text


class DR2DPMessageRemoveFlow(DR2DPMessage1):

    # The on-the-wire format:
    #    4B  src_addr
    #    4B  dst_addr
    #    2B  src_port
    #    2B  dst_port
    #    1B  protocol
    #    3B  padding
    #
    REMOVE_HFORMAT = '!4s4sHHB3B'
    REMOVE_HLENGTH = struct.calcsize(REMOVE_HFORMAT)

    def __init__(self, src_addr, dst_addr, src_port, dst_port, protocol):

        try:
           super(DR2DPMessageRemoveFlow, self).__init__(
               DR2DPMessage1.MESSAGE_TYPE_REQUEST,
               DR2DPMessage1.OP_TYPE_REMOVE_FLOW)
        except TypeError, ValueError:
            raise

        if type(src_port) != int:
            raise TypeError('illegal src_port type (%s)' % (
                            (str(type(src_port))),))

        if type(dst_port) != int:
            raise TypeError('illegal dst_port type (%s)' % (
                            (str(type(dst_port))),))

        if type(protocol) != int:
            raise TypeError('illegal protocol type (%s)' % (
                            (str(type(protocol))),))

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        DEBUG and debug("RemoveFlow: %s" % str(self))

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageRemoveFlow.REMOVE_HFORMAT,
                          self.src_addr, self.dst_addr,
                          self.src_port, self.dst_port, self.protocol, 0, 0, 0)

        DEBUG and debug("RemoveFlow: pack %s" % str(self))
        return super(DR2DPMessageRemoveFlow, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) != DR2DPMessageRemoveFlow.REMOVE_HLENGTH:
            raise ValueError('insufficient data buffer for remove message')
            return

        (src_addr, dst_addr,
         src_port, dst_port,
         protocol,
         pad1, pad2, pad3) = struct.unpack(
                                 DR2DPMessageRemoveFlow.REMOVE_HFORMAT,
                                 self.data)

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        DEBUG and debug("RemoveFlow: unpack %s" % str(self))

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageRemoveFlow, self).__str__()
        text += '\n'
        text += '    RemoveFlow '
        text += '(%s,' % socket.inet_ntoa(self.src_addr)
        text += ' %s,' % socket.inet_ntoa(self.dst_addr)
        text += ' %s,' % self.src_port
        text += ' %s,' % self.dst_port
        text += ' %s)' % self.protocol

        return text


class DR2DPMessageReassignFlow(DR2DPMessage1):

    # The on-the-wire format:
    #    XXX TODO What is the format of a dpid? Assuming IP addr for now.
    #    4B  dpid (decoy proxy identifier)
    #    4B  src_addr
    #    4B  dst_addr
    #    2B  src_port
    #    2B  dst_port
    #    1B  protocol
    #    3B  padding
    #
    REASSIGN_HFORMAT = '!4s4s4sHHB3B'
    REASSIGN_HLENGTH = struct.calcsize(REASSIGN_HFORMAT)

    def __init__(self, dpid, src_addr, dst_addr, src_port, dst_port, protocol):

        try:
            super(DR2DPMessageReassignFlow, self).__init__(
                DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_REASSIGN_FLOW)
        except TypeError, ValueError:
            raise

        if type(src_port) != int:
            raise TypeError('illegal src_port type (%s)' % (
                            (str(type(src_port))),))

        if type(dst_port) != int:
            raise TypeError('illegal dst_port type (%s)' % (
                            (str(type(dst_port))),))

        if type(protocol) != int:
            raise TypeError('illegal protocol type (%s)' % (
                            (str(type(protocol))),))

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.dpid = dpid
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        DEBUG and debug("ReassignFlow: %s" % str(self))

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageReassignFlow.REASSIGN_HFORMAT,
                          socket.inet_aton(self.dpid),
                          socket.inet_aton(self.src_addr),
                          socket.inet_aton(self.dst_addr),
                          self.src_port, self.dst_port, self.protocol, 0, 0, 0)

        DEBUG and debug("ReassignFlow: pack %s" % str(self))
        return super(DR2DPMessageReassignFlow, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) != DR2DPMessageReassignFlow.REASSIGN_HLENGTH:
            raise ValueError('insufficient data buffer for reassign message')
            return

        (dpid, src_addr, dst_addr,
         src_port, dst_port,
         protocol,
         pad1, pad2, pad3) = struct.unpack(
                                 DR2DPMessageReassignFlow.REASSIGN_HFORMAT,
                                 self.data)

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.dpid = socket.inet_ntoa(dpid)
        self.src_addr = socket.inet_ntoa(src_addr)
        self.dst_addr = socket.inet_ntoa(dst_addr)
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        DEBUG and debug("ReassignFlow: unpack %s" % str(self))

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageReassignFlow, self).__str__()
        text += '\n'
        text += '    ReassignFlow'
        text += ' %s ' % self.dpid
        text += '(%s,' % self.src_addr
        text += ' %s,' % self.dst_addr
        text += ' %s,' % self.src_port
        text += ' %s,' % self.dst_port
        text += ' %s)' % self.protocol

        return text


class DR2DPMessageTLSFlowEstablished(DR2DPMessage1):

    # The on-the-wire format:
    #    4B  src_addr
    #    4B  dst_addr
    #    2B  src_port
    #    2B  dst_port
    #    1B  protocol
    #    3B  padding
    #   28s  random_number (28 byte random number string)
    TLS_HFORMAT = '!4s4sHHB3B28s'
    TLS_HLENGTH = struct.calcsize(TLS_HFORMAT)

    def __init__(self, src_addr, dst_addr,
                       src_port, dst_port, protocol, random_number):

        try:
            super(DR2DPMessageTLSFlowEstablished, self).__init__(
                DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED)
        except TypeError, ValueError:
            raise

        if type(src_port) != int:
            raise TypeError('illegal src_port type (%s)' % (
                            (str(type(src_port))),))

        if type(dst_port) != int:
            raise TypeError('illegal dst_port type (%s)' % (
                            (str(type(dst_port))),))

        if type(protocol) != int:
            raise TypeError('illegal protocol type (%s)' % (
                            (str(type(protocol))),))

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        if len(random_number) != 28:
            raise ValueError('invalid random_number length (%d)' %
                             (len(random_number),))

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.random_number = random_number
        DEBUG and debug("TLSFlowEstablished: %s" % str(self))

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageTLSFlowEstablished.TLS_HFORMAT,
                          socket.inet_aton(self.src_addr),
                          socket.inet_aton(self.dst_addr),
                          self.src_port, self.dst_port, self.protocol,
                          0, 0, 0, self.random_number)

        DEBUG and debug("TLSFlowEstablished: pack %s" % str(self))
        return super(DR2DPMessageTLSFlowEstablished, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) != DR2DPMessageTLSFlowEstablished.TLS_HLENGTH:
            raise ValueError('insufficient data buffer for tls message')
            return

        (src_addr, dst_addr,
         src_port, dst_port,
         protocol, pad1, pad2, pad3,
         self.random_number) = struct.unpack(
                                   DR2DPMessageTLSFlowEstablished.TLS_HFORMAT,
                                   self.data)

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.src_addr = socket.inet_ntoa(src_addr)
        self.dst_addr = socket.inet_ntoa(dst_addr)
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        DEBUG and debug("TLSFlowEstablished: unpack %s" % str(self))

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageTLSFlowEstablished, self).__str__()
        text += '\n'
        text += '    TLSFlowEstablished '
        text += '(%s,' % self.src_addr
        text += ' %s,' % self.dst_addr
        text += ' %s,' % self.src_port
        text += ' %s,' % self.dst_port
        text += ' %s)' % self.protocol
        text += '\n'
        text += '                       %s'  % self.random_number

        return text

class DR2DPMessageICMP(DR2DPMessage1):

    # The on-the-wire format:
    #    4B  src_addr
    #    4B  dst_addr
    #    2B  src_port
    #    2B  dst_port
    #    1B  protocol
    #    1B  flags
    #    2B  padding
    #        packet (variable length)
    ICMP_HFORMAT = '!4s4sHHBBH'
    ICMP_HLENGTH = struct.calcsize(ICMP_HFORMAT)

    ICMP_FLAG_TO_CLIENT = 0x01

    def __init__(self, src_addr, dst_addr,
                       src_port, dst_port, protocol, flags, packet):

        try:
            super(DR2DPMessageICMP, self).__init__(
                DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_ICMP)
        except TypeError, ValueError:
            raise

        if type(src_port) != int:
            raise TypeError('illegal src_port type (%s)' % (
                            (str(type(src_port))),))

        if type(dst_port) != int:
            raise TypeError('illegal dst_port type (%s)' % (
                            (str(type(dst_port))),))

        if type(protocol) != int:
            raise TypeError('illegal protocol type (%s)' % (
                            (str(type(protocol))),))

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.flags = flags
        self.packet = packet
        DEBUG and debug("ICMP: %s" % str(self))

    def get_tuple(self):
        return (self.src_addr, self.src_port, self.dst_addr, self.dst_port)

    def is_reverse(self):
        return (self.flags & DR2DPMessageICMP.ICMP_FLAG_TO_CLIENT)

    def get_pkt(self):
        return self.packet

    def pack(self):
        """
        Convert to wire format.
        """

        msg = struct.pack(DR2DPMessageICMP.ICMP_HFORMAT,
                          self.src_addr, self.dst_addr,
                          self.src_port, self.dst_port, self.protocol,
                          self.flags, 0)
        msg += self.packet

        DEBUG and debug("ICMP: pack %s" % str(self))
        return super(DR2DPMessageICMP, self).pack(msg)

    def unpack(self):
        """
        Parse data buffer.
        """

        if len(self.data) < DR2DPMessageICMP.ICMP_HLENGTH:
            raise ValueError('insufficient data buffer for icmp message')
            return

        header_buf = self.data[:DR2DPMessageICMP.ICMP_HLENGTH]
        (src_addr, dst_addr,
         src_port, dst_port,
         protocol, flags, pad) = struct.unpack(
                                     DR2DPMessageICMP.ICMP_HFORMAT, header_buf)

        if src_port <= 0 or src_port > 65535:
            raise ValueError('invalid src_port value (%d)' % (src_port,))

        if dst_port <= 0 or dst_port > 65535:
            raise ValueError('invalid dst_port value (%d)' % (dst_port,))

        if protocol < 0 or protocol > 15:
            raise ValueError('invalid protocol value (%d)' % (protocol,))

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.flags = flags
        self.packet = self.data[DR2DPMessageICMP.ICMP_HLENGTH:]
        DEBUG and debug("ICMP: unpack %s" % str(self))

    def __str__(self):
        """
        Produce string format of message content.
        """

        text = super(DR2DPMessageICMP, self).__str__()
        text += '\n'
        text += '    ICMP '
        text += '(%s,' % self.src_addr
        text += ' %s,' % self.dst_addr
        text += ' %s,' % self.src_port
        text += ' %s,' % self.dst_port
        text += ' %s)' % self.protocol
        text += ' flags %s' % hex(self.flags)
        text += ' %s' % self.packet

        return text

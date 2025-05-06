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
Implementation of the Sentman Request Format
"""

import logging
import struct

import cb.util.cblogging

class SentmanRequestUnpackError(BaseException):
    """
    An exception raised when a bad Sentman message is unpacked from data
    """

    pass

class SentmanRequest(object):
    """
    Implementation of a Sentman Request Message
    """

    PROTOCOL_VERSION = 1

    # Request types:
    #
    ALLOCATE_SENTINEL = 1
    GET_INFO = 2

    FORMAT = '!BBH'
    MESSAGE_LEN = struct.calcsize(FORMAT)

    # Mnemonic names for the message types.
    #
    MSG_TYPES = {
            ALLOCATE_SENTINEL : 'alloc',
            GET_INFO : 'getinfo'
            }

    LOGGER = logging.getLogger('cb.sentman')

    def __init__(self, op_type):

        if type(op_type) != int:
            err_str = 'bad request op type (%s != int)' % str(type(op_type))
            SentmanRequest.LOGGER.warn(err_str)
            raise TypeError(err_str)

        if not op_type in SentmanRequest.MSG_TYPES:
            err_str = 'bad request op value (%u)' % op_type
            SentmanRequest.LOGGER.warn(err_str)
            raise ValueError(err_str)

        # Phew!  Everything looks OK.
        #
        self.op_type = op_type
        self.version = SentmanRequest.PROTOCOL_VERSION
        self.msg_len = SentmanRequest.MESSAGE_LEN

    def get_version(self):
        """ Return the protocol version """
        return self.version

    def get_op_type(self):
        """ Return the op type """
        return self.op_type

    def get_msg_len(self):
        """ Return the msg_len """
        return self.msg_len

    @staticmethod
    def alloc_request():
        """ Create an 'alloc' request """
        return SentmanRequest(SentmanRequest.ALLOCATE_SENTINEL)

    @staticmethod
    def info_request():
        """ Create an 'getinfo' request """
        return SentmanRequest(SentmanRequest.GET_INFO)

    def pack(self):
        """
        Create a string containing the on-the-wire string representation
        of this SentmanRequest instance.

        DOES NO ERROR CHECKING.  If someone has changed the value of the fields
        after they were validated by __init__, then they could be wrong and this
        won't detect it.

        TODO: consider whether we want to do another validation here.  Right now
        we use the fact that we can create bogus messages to test what happens
        when we try to recv them.
        """

        msg = struct.pack(SentmanRequest.FORMAT,
                self.version, self.op_type, self.msg_len)
        return msg

    def __str__(self):
        """ Create a human-readable string representation """

        if self.op_type in SentmanRequest.MSG_TYPES:
            op_name = SentmanRequest.MSG_TYPES[self.op_type]
        else:
            op_name = '?(%u)' % (self.op_type,)

        return 'SentmanRequest: ver %u op_type %s' % (self.version, op_name)

    def send(self, sock):
        """ Send the request via the given socket """
        return sock.send(self.pack())

    @staticmethod
    def recv(recv_buffer):
        """
        Given a buffer that contains some fraction of SentmanRequests, parse any
        out and put them in a msgs array, removing them from the buffer as we go
        """

        request_len = SentmanRequest.MESSAGE_LEN

        msgs = []
        while True:
            if len(recv_buffer) < request_len:
                return (msgs, recv_buffer)

            first = recv_buffer[:request_len]
            recv_buffer = recv_buffer[request_len:]

            (version, op_type, msg_len) = struct.unpack(
                    SentmanRequest.FORMAT, first)

            SentmanRequest.LOGGER.debug(
                    'version %u; op_type %u; msg_len: %u' %
                    (version, op_type, msg_len))

            # Now that we have the entire message, we can decide whether it's
            # valid.
            #
            if version != SentmanRequest.PROTOCOL_VERSION:
                err_str = 'bad version (%u)' % (version,)
                SentmanRequest.LOGGER.warn(err_str)
                raise SentmanRequestUnpackError(err_str)

            if not op_type in SentmanRequest.MSG_TYPES:
                err_str = 'bad op_type (%u)' % (op_type,)
                SentmanRequest.LOGGER.warn(err_str)
                raise SentmanRequestUnpackError(err_str)

            if msg_len != SentmanRequest.MESSAGE_LEN:
                err_str = 'bad msg_len (%u)' % (msg_len,)
                SentmanRequest.LOGGER.warn(err_str)
                raise SentmanRequestUnpackError(err_str)

            # The message is complete and valid.  Append it to the list of
            # messages we've received.
            #
            msgs.append(SentmanRequest(op_type))


if __name__ == '__main__': # UNIT TEST

    def test_basic():
        """
        Test the basic packing/unpacking for well-formed requests
        """

        test_extra = 'ugh'

        req1 = SentmanRequest(SentmanRequest.ALLOCATE_SENTINEL)

        # make sure that we can pack and then recv.
        req1_buf = req1.pack()
        (msgs, buf) = SentmanRequest.recv(req1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(req1))
        assert(buf == '')

        # make sure that we can pack and then recv with a partial
        req1_buf = req1.pack() + test_extra
        (msgs, buf) = SentmanRequest.recv(req1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(req1))
        assert(buf == test_extra)

        # make sure that we can pack and then recv multiple
        req1_buf = req1.pack() * 2
        (msgs, buf) = SentmanRequest.recv(req1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(req1))
        assert(str(msgs[1]) == str(req1))
        assert(buf == '')

        # make sure that we can pack and then recv multiple plus a partial
        req1_buf = (req1.pack() * 2) + test_extra
        (msgs, buf) = SentmanRequest.recv(req1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(req1))
        assert(str(msgs[1]) == str(req1))
        assert(buf == test_extra)

    def test_bogus():
        """
        Test that bogus requests are detected
        """

        # Find a bogus op_type by trial and error
        #
        bogus_op_type = -1
        for bogus_op_type in range(0, 1000):
            if not bogus_op_type in SentmanRequest.MSG_TYPES:
                break

        req1 = SentmanRequest(SentmanRequest.ALLOCATE_SENTINEL)
        req1.op_type = bogus_op_type
        req1_buf = req1.pack()
        try:
            (_msgs, _buf) = SentmanRequest.recv(req1_buf)
        except SentmanRequestUnpackError, _exc:
            print "Bogus op_type detected"
        else:
            print "Didn't catch bogus op_type"

        req1 = SentmanRequest(SentmanRequest.ALLOCATE_SENTINEL)
        req1.version = SentmanRequest.PROTOCOL_VERSION + 20
        req1_buf = req1.pack()
        try:
            (_msgs, _buf) = SentmanRequest.recv(req1_buf)
        except SentmanRequestUnpackError, _exc:
            print "Bogus version detected"
        else:
            print "Didn't catch bogus version"

        req1 = SentmanRequest(SentmanRequest.ALLOCATE_SENTINEL)
        req1.msg_len = SentmanRequest.MESSAGE_LEN + 33
        req1_buf = req1.pack()
        try:
            (_msgs, _buf) = SentmanRequest.recv(req1_buf)
        except SentmanRequestUnpackError, _exc:
            print "Bogus msg_len detected"
        else:
            print "Didn't catch bogus msg_len"

    def test_main():
        """ unit test driver """

        test_basic()
        test_bogus()

        return 0

    exit(test_main())

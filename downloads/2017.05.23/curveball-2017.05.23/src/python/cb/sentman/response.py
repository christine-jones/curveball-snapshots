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
Implementation of the Sentman Response Format
"""

import binascii
import logging
import struct

import cb.util.cblogging

class SentmanResponseUnpackError(BaseException):
    """
    An exception raised when a bad Sentman response message is
    unpacked from data
    """

    pass

class SentmanResponse(object):
    """
    Implementation of a Sentman Response Message
    """

    PROTOCOL_VERSION = 1

    # Response types:
    #
    STATUS_SUCCESS = 0
    STATUS_EXHAUSTED = 1
    STATUS_INVALID = 2

    SENTINEL_LEN = 32
    UNKNOWN_REMAINING = 0xffffffff
    UNKNOWN_EPOCH = 0xffffffff

    FORMAT = '!BBHLL%ds' % SENTINEL_LEN
    MESSAGE_LEN = struct.calcsize(FORMAT)

    # Mnemonic names for the message types.
    #
    MSG_TYPES = {
            STATUS_SUCCESS : 'success',
            STATUS_EXHAUSTED : 'exhausted',
            STATUS_INVALID : 'invalid'
            }

    LOGGER = logging.getLogger('cb.sentman')

    def __init__(self, status, sentinel, remaining=UNKNOWN_REMAINING,
            epoch=UNKNOWN_EPOCH):

        if type(status) != int:
            err_str = 'bad status (%s != int)' % str(type(status))
            SentmanResponse.LOGGER.warn(err_str)
            raise TypeError(err_str)

        if not status in SentmanResponse.MSG_TYPES:
            err_str = 'bad status value (%u)' % status
            SentmanResponse.LOGGER.warn(err_str)
            raise ValueError(err_str)

        if type(sentinel) != str:
            err_str = 'sentinel must be a str (not %s)' % str(type(sentinel))
            SentmanResponse.LOGGER.warn(err_str)
            raise TypeError(err_str)

        if len(sentinel) != SentmanResponse.SENTINEL_LEN:
            err_str = 'sentinel is the wrong length (%d should be %d)' % (
                    len(sentinel), SentmanResponse.SENTINEL_LEN)
            SentmanResponse.LOGGER.warn(err_str)
            raise ValueError(err_str)

        if (remaining < 0) or (remaining > SentmanResponse.UNKNOWN_REMAINING):
            err_str = 'remaining is bogus (%d)' % remaining
            SentmanResponse.LOGGER.warn(err_str)
            raise ValueError(err_str)

        if (epoch < 0) or (epoch > SentmanResponse.UNKNOWN_EPOCH):
            err_str = 'epoch is bogus (%d)' % epoch
            SentmanResponse.LOGGER.warn(err_str)
            raise ValueError(err_str)

        # Phew!  Everything looks OK.
        #
        self.status = status
        self.version = SentmanResponse.PROTOCOL_VERSION
        self.msg_len = SentmanResponse.MESSAGE_LEN
        self.remaining = remaining
        self.epoch = epoch
        self.sentinel = sentinel

    def get_version(self):
        """ Return the protocol version """
        return self.version

    def get_status(self):
        """ Return the status """
        return self.status

    def get_msg_len(self):
        """ Return the msg_len """
        return self.msg_len

    def get_remaining(self):
        """ Return the remaining # of sentinels, if known """
        return self.remaining

    def get_epoch(self):
        """ Return the remaining # of seconds in the epoch, if known """
        return self.epoch

    def get_sentinel(self):
        """ Return the sentinel """
        return self.sentinel

    def pack(self):
        """
        Create a string containing the on-the-wire string representation
        of this SentmanResponse instance.

        DOES NO ERROR CHECKING.  If someone has changed the value of the fields
        after they were validated by __init__, then they could be wrong and this
        won't detect it.

        TODO: consider whether we want to do another validation here.  Right now
        we use the fact that we can create bogus messages to test what happens
        when we try to recv them.
        """

        msg = struct.pack(SentmanResponse.FORMAT,
                self.version, self.status, self.msg_len,
                self.remaining, self.epoch, self.sentinel)
        return msg

    def __str__(self):
        """ Create a human-readable string representation """

        if self.status in SentmanResponse.MSG_TYPES:
            status_name = SentmanResponse.MSG_TYPES[self.status]
        else:
            status_name = '?(%u)' % (self.status,)

        fmt = ('SentmanResponse: ver %u status %s remaining %x epoch %x ' +
                'sentinel %s')

        return fmt % (self.version, status_name, self.remaining, self.epoch,
                binascii.hexlify(self.sentinel))

    def send(self, sock):
        """ Send the response via the given socket """
        return sock.send(self.pack())

    @staticmethod
    def recv(recv_buffer):
        """
        Given a buffer that contains some fraction of SentmanResponses, parse
        any out and put them in a msgs array, removing them from the buffer as
        we go
        """

        response_len = SentmanResponse.MESSAGE_LEN

        fmt = 'ver %u status %s remaining %x epoch %x sentinel %s'

        msgs = []
        while True:
            if len(recv_buffer) < response_len:
                return (msgs, recv_buffer)

            first = recv_buffer[:response_len]
            recv_buffer = recv_buffer[response_len:]

            (version, status, msg_len, remaining, epoch, sentinel) = \
                    struct.unpack(SentmanResponse.FORMAT, first)

            SentmanResponse.LOGGER.debug(fmt %
                    (version, status, remaining, epoch, sentinel))

            # Now that we have the entire message, we can decide whether it's
            # valid.
            #
            if version != SentmanResponse.PROTOCOL_VERSION:
                err_str = 'bad version (%u)' % (version,)
                SentmanResponse.LOGGER.warn(err_str)
                raise SentmanResponseUnpackError(err_str)

            if not status in SentmanResponse.MSG_TYPES:
                err_str = 'bad status (%u)' % (status,)
                SentmanResponse.LOGGER.warn(err_str)
                raise SentmanResponseUnpackError(err_str)

            if msg_len != SentmanResponse.MESSAGE_LEN:
                err_str = 'bad msg_len (%u)' % (msg_len,)
                SentmanResponse.LOGGER.warn(err_str)
                raise SentmanResponseUnpackError(err_str)

            # There is probably more error checking to do here.

            # The message is complete and valid.  Append it to the list of
            # messages we've received.
            #
            msgs.append(SentmanResponse(status, sentinel, remaining, epoch))


if __name__ == '__main__': # UNIT TEST

    def test_basic():
        """
        Test the basic packing/unpacking for well-formed requests
        """

        test_extra = 'bogus'
        sentinel = 'And then fold in the other flour'

        res1 = SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)

        # make sure that we can pack and then recv.
        res1_buf = res1.pack()
        (msgs, buf) = SentmanResponse.recv(res1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(res1))
        assert(buf == '')

        # make sure that we can pack and then recv with a partial
        res1_buf = res1.pack() + test_extra
        (msgs, buf) = SentmanResponse.recv(res1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(res1))
        assert(buf == test_extra)

        # make sure that we can pack and then recv multiple
        res1_buf = res1.pack() * 2
        (msgs, buf) = SentmanResponse.recv(res1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(res1))
        assert(str(msgs[1]) == str(res1))
        assert(buf == '')

        # make sure that we can pack and then recv multiple plus a partial
        res1_buf = (res1.pack() * 2) + test_extra
        (msgs, buf) = SentmanResponse.recv(res1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(res1))
        assert(str(msgs[1]) == str(res1))
        assert(buf == test_extra)

    def test_bogus():
        """
        Test that bogus resuests are detected
        """

        success = True

        sentinel = 12
        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)
        except TypeError, exc:
            print 'Bogus sentinel type detected: %s' % str(exc)
        else:
            print "Didn't catch bogus sentinel"
            success = False

        sentinel = 'short string'
        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)
        except ValueError, exc:
            print 'Short sentinel detected: %s' % str(exc)
        else:
            print "Didn't catch bogus sentinel"
            success = False

        sentinel = 'Do not forget the chopped onions'

        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel,
                    remaining=-1)
        except ValueError, exc:
            print 'bogus remaining detected: %s' % str(exc)
        else:
            print "Didn't catch bogus remaining"
            success = False

        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel,
                    remaining=SentmanResponse.UNKNOWN_REMAINING + 1)
        except ValueError, exc:
            print 'bogus remaining detected: %s' % str(exc)
        else:
            print "Didn't catch bogus remaining"
            success = False

        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel,
                    epoch=-1)
        except ValueError, exc:
            print 'bogus epoch detected: %s' % str(exc)
        else:
            print "Didn't catch bogus epoch"
            success = False

        try:
            SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel,
                    epoch=SentmanResponse.UNKNOWN_EPOCH + 1)
        except ValueError, exc:
            print 'bogus epoch detected: %s' % str(exc)
        else:
            print "Didn't catch bogus epoch"
            success = False

        # Find a bogus status by trial and error
        #
        bogus_status = -1
        for bogus_status in range(0, 1000):
            if not bogus_status in SentmanResponse.MSG_TYPES:
                break

        res1 = SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)
        res1.status = bogus_status
        res1_buf = res1.pack()
        try:
            (_msgs, _buf) = SentmanResponse.recv(res1_buf)
        except SentmanResponseUnpackError, exc:
            print "Bogus status detected: %s" % str(exc)
        else:
            print "Didn't catch bogus status"
            success = False

        res1 = SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)
        res1.version = SentmanResponse.PROTOCOL_VERSION + 20
        res1_buf = res1.pack()
        try:
            (_msgs, _buf) = SentmanResponse.recv(res1_buf)
        except SentmanResponseUnpackError, exc:
            print "Bogus version detected: %s" % str(exc)
        else:
            print "Didn't catch bogus version"
            success = False

        res1 = SentmanResponse(SentmanResponse.STATUS_SUCCESS, sentinel)
        res1.msg_len = SentmanResponse.MESSAGE_LEN + 33
        res1_buf = res1.pack()
        try:
            (_msgs, _buf) = SentmanResponse.recv(res1_buf)
        except SentmanResponseUnpackError, exc:
            print "Bogus msg_len detected: %s" % str(exc)
        else:
            print "Didn't catch bogus msg_len"
            success = False

        return success

    def test_main():
        """ unit test driver """

        test_basic()

        if not test_bogus():
            print 'FAILED test_bogus()'
            return 1

        return 0

    exit(test_main())

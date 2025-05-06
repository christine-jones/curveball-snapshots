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
Implementation of the Covert Channel Protocol Message Format
"""

import logging
import struct

import cb.util.cblogging
import sys
import binascii

import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))
# might make this CCPMessage.LOGGER.debug
def log_debug(msg):
    print >> sys.stderr, "ccp: %s" % msg


class CCPMessageUnpackError(BaseException):
    """
    An exception raised when a bad CCP message is unpacked from data (typically
    data received over a CCP connection)
    """

    pass

class CCPMessage(object):
    """
    Implementation of a Covert Channel Protocol Message
    """

    # The message format is intended to be dead simple, not efficient (although
    # for most of the messages, which are likely to be data transfers of at
    # least a hundred bytes or so, it's efficient enough).  Every message
    # contains every field (although the data payload may be zero-length)
    # whether or not it is strictly necessary.  This makes message encoding and
    # decoding very simple.
    #
    # Each message has a header that contains the following fields :
    #
    # Protocol Version (1 byte): always 1 for this version of the protocol.
    #
    # Message Type (1 byte): see below.
    #
    # Connection Identifier (36 bytes; a UUID chosen by the client plus a 16-bit
    # offset, also chosen by the client, expressed as a hex string)
    #
    # Data Payload length (in bytes; 2 bytes, unsigned)

    # We only have one version of the protocol
    #
    # FIXME - we're sloppy about checking that the protocol version matches what
    # it is supposed to be.
    #
    PROTOCOL_VERSION = 2

    # Message types:
    #
    # Initiate a new SOCKS connection (client to server)
    #
    OPEN_SOCKS5_CONN = 1

    # Close the connection (either to either)
    #
    CLOSE_CONNECTION = 3

    # Transfer data from client to server (client app 'send')
    #
    DATA_SEND = 4

    # Transfer data from server to client (server proxy 'send'; client recv)
    #
    DATA_RECV = 5

    # Added for VPN tunnel mode
    #
    PKT_SEND = 6
    PKT_RECV = 7

    # Acknowledge an open connection
    OPEN_CONNECTION_ACK = 8

    # Initiate a new CVPN connection (client to server)
    OPEN_CVPN_CONN = 9

    # Mnemonic names for the message types.
    #
    msg_types = {
            OPEN_SOCKS5_CONN : 'open-socks5',
            OPEN_CVPN_CONN : 'open-cvpn',
            CLOSE_CONNECTION : 'close',
            DATA_SEND : 'send',
            DATA_RECV : 'recv',
            PKT_SEND : 'pkt_send',
            PKT_RECV : 'pkt_recv',
            OPEN_CONNECTION_ACK : 'open_ack'
            }


    # Connection types:
    CONN_TYPE_SOCKS = 0
    CONN_TYPE_CVPN = 1

    con_types = {
            CONN_TYPE_SOCKS : 'socks5',
            CONN_TYPE_CVPN : 'cvpn'
            }

    # conn_id used for the chaff connection.  Any data or pkt received for
    # this conn_id is discarded.
    #
    CHAFF_CONN_ID = 0xfffffffe

    # Maximum allowed data message payload length.
    #
    # NOTE: must always be less than 64K, because the length field is 16 bits.
    # A reasonable maximum is 4KB.
    #
    MAX_DATA_LEN = 4 * 1024

    # The header format, as used by struct.pack.
    #
    HEADER_FMT = '!BBHL'

    LOGGER = logging.getLogger('cb.ccp')

    def __init__(self, msg_type, conn_id, data=None):

        # self.logger = logging.getLogger('cb.ccp')

        if not data:
            data = ''

        data_len = len(data)

        if (data_len > CCPMessage.MAX_DATA_LEN):
            err_str = 'bad data_len (%u)' % (data_len,)
            CCPMessage.LOGGER.warn(err_str)
            raise ValueError(err_str)

        if not msg_type in self.msg_types:
            err_str = 'bad msg_type (%u)' % (msg_type,)
            CCPMessage.LOGGER.warn(err_str)
            raise ValueError(err_str)


        # TODO - it also has to be a msg_type that we expect
        # (not all messages are valid over all CCP connections)

        # Phew!  Everything looks OK.
        #
        self._version = CCPMessage.PROTOCOL_VERSION
        self._msg_type = msg_type
        self._conn_id = conn_id
        self._data = data

        # CCPMessage.LOGGER.debug("connection ID: %s" % (conn_id,))


    def get_version(self):
        """ Return the protocol version of this CCPMessage """
        return self._version


    def get_msg_type(self):
        """ Return the message type of this CCPMessage """
        return self._msg_type


    def get_conn_id(self):
        """ Return the connection ID of this CCPMessage """
        return self._conn_id


    def get_data(self):
        """ Return the data payload of this CCPMessage """
        return self._data


    @staticmethod
    def open_socks_msg(conn_id):
        """ Create an 'open-socks5' CCPMessage instance """
        return CCPMessage(CCPMessage.OPEN_SOCKS5_CONN, conn_id=conn_id)

    @staticmethod
    def open_cvpn_msg(conn_id):
        """ Create an 'open-cvpn' CCPMessage instance """
        return CCPMessage(CCPMessage.OPEN_CVPN_CONN, conn_id=conn_id)

    @staticmethod
    def open_ack_msg(conn_id):
        """ Create an 'open_ack' CCPMessage instance """
        return CCPMessage(CCPMessage.OPEN_CONNECTION_ACK, conn_id=conn_id)

    @staticmethod
    def close_msg(conn_id):
        """ Create a 'close' CCPMessage instance """
        return CCPMessage(CCPMessage.CLOSE_CONNECTION, conn_id=conn_id)


    @staticmethod
    def data_send(conn_id, buf):
        """ Create a 'send' CCPMessage instance """
        return CCPMessage(CCPMessage.DATA_SEND, conn_id=conn_id, data=buf)


    @staticmethod
    def data_recv(conn_id, buf):
        """ Create a 'recv' CCPMessage instance """
        return CCPMessage(CCPMessage.DATA_RECV, conn_id=conn_id, data=buf)


    @staticmethod
    def pkt_send(conn_id, pkt_buf):
        """ Create a 'pkt_send' CCPMessage instance """
        return CCPMessage(CCPMessage.PKT_SEND, conn_id=conn_id, data=pkt_buf)


    @staticmethod
    def pkt_recv(conn_id, pkt_buf):
        """ Create a 'pkt_recv' CCPMessage instance """
        return CCPMessage(CCPMessage.PKT_RECV, conn_id=conn_id, data=pkt_buf)


    @staticmethod
    def chaff_msg(length, buf=''):
        """
        Create an 'open-chaff' CCPMessage instance with the given length.

        The buf, if provided, is used as the prefix for the message.  If buf
        isn't long enough to fill the given length, fill the remainder with '+'
        characters.

        NOTE: it is better to pass in a buffer of chaff that has reasonable
        properties than it is to rely on this method to create the buffer,
        since it creates a buffer with known plaintext.
        """

        if length <= 0:
            contents = ''
        elif not buf:
            contents = '+' * length
        else:
            contents = buf[:length]
            if len(contents) < length:
                contents += '+' * (length - len(contents))

        return CCPMessage(CCPMessage.DATA_SEND,
                conn_id=CCPMessage.CHAFF_CONN_ID, data=contents)


    def pack(self):
        """
        Create a string containing the on-the-wire string representation
        of this CCPMessage instance.

        DOES NO ERROR CHECKING.  If someone has changed the value of the fields
        after they were validated by __init__, then they could be wrong and this
        won't detect it.  TODO: consider whether we want to do another
        validation here.  Right now we use the fact that we can create bogus
        messages to test what happens when we try to recv them.
        """

        datalen = 0
        if self._data:
            datalen = len(self._data)

        header = struct.pack(CCPMessage.HEADER_FMT,
                self._version, self._msg_type, datalen, self._conn_id )

        if datalen > 0:
            msg = header + self._data
        else:
            msg = header

        return msg


    def __str__(self):
        """ Create a human-readable string representation """

        if self._msg_type in self.msg_types:
            msg_type_name = self.msg_types[self._msg_type]
        else:
            msg_type_name = '?(%u)' % (self._msg_type,)

        return 'CCPMessage: ver %u msg_type %s conn_id %s data [%s]' % (
                self._version, msg_type_name, self._conn_id, self._data)


    def send(self, sock):
        """ Send the message via the given socket """
        return sock.send(self.pack())


    @staticmethod
    def recv(recv_buffer):
        """
        Given a buffer that contains some fraction of CCP messages, parse
        any out and put them in a msgs array, removing them from the buffer
        as we go
        """

        header_len = struct.calcsize(CCPMessage.HEADER_FMT)

        msgs = []
        while True:
            if len(recv_buffer) < header_len:
                #print "AAAAAAAAAAAAAA %s " % str(len(recv_buffer))
                return (msgs, recv_buffer)

            header = recv_buffer[:header_len]

            (version, msg_type, data_len, conn_id) = struct.unpack(
                    CCPMessage.HEADER_FMT, header)

            DEBUG and log_debug("msg %d: version: %r; msg_type: %r; data_len: %u; conn_id: %r"
                                % (len(msgs), version, msg_type, data_len, conn_id))


            #print("msg %d: version: %r; msg_type: %r; data_len: %u; conn_id: %r"
            #                    % (len(msgs), version, msg_type, data_len, conn_id))

            if DEBUG:
                top1 = len(recv_buffer)
                top2 = len(recv_buffer)
                if top1 > 64:
                    top1 = 64
                    if top2 > 128:
                        top2 = 128

                log_debug("first %d bytes of data: %s" %
                        (top1, binascii.b2a_hex(recv_buffer[0:top1])))
                if top2 > 64:
                    log_debug("second %d bytes of data: %s" %
                            (top2 - top1,
                                binascii.b2a_hex(recv_buffer[top1:top2])))

            # check to make sure that the data_len is sane.  We defer the other
            # checks until we have the entire packet, but this needs to be done
            # first in order to prevent an adversary from gumming up the
            # connection by sending an impossibly long message.
            if data_len > CCPMessage.MAX_DATA_LEN:
                #print "BBBBBBB bad data len"
                err_str = 'bad data_len (%u), recv_buffer len: %d' % (data_len,
                                                                      len(recv_buffer))
                CCPMessage.LOGGER.warn(err_str)

                raise CCPMessageUnpackError(err_str)

            # if we haven't received an entire message yet, then return
            #
            if len(recv_buffer) < (header_len + data_len):
                #print "CCCCCCCCCCCCCCCCCCCCCCCC len(recv_buffer) < %s " % str(header_len + data_len)
                #print str(len(recv_buffer))
                return (msgs, recv_buffer)

            if data_len == 0:
                data = None
            else:
                data = recv_buffer[header_len:header_len + data_len]

            recv_buffer = recv_buffer[header_len + data_len:]

            # Now that we have the entire message, we can decide whether it's
            # valid.
            #
            if version != CCPMessage.PROTOCOL_VERSION:
                err_str = 'bad version (%u)' % (version,)
                CCPMessage.LOGGER.warn(err_str)
                raise CCPMessageUnpackError(err_str)

            if not msg_type in CCPMessage.msg_types:
                err_str = 'bad msg_type (%u)' % (msg_type,)
                CCPMessage.LOGGER.warn(err_str)
                raise CCPMessageUnpackError(err_str)

            # The message is complete and valid.  Append it to the list of
            # messages we've received.
            #
            msgs.append(CCPMessage(msg_type, conn_id=conn_id, data=data))

            # CCPMessage.LOGGER.debug("received msg_type (%u)" %
            #         (msg_type,))


if __name__ == '__main__': # UNIT TEST

    def test_main():
        """ unit test driver """

        # TODO - this doesn't really test much of anything

        test_extra = 'blah'

        # Find a bogus msg_type by trial and error
        #
        for bogus_msg_type in range(0, 1000):
            if not bogus_msg_type in CCPMessage.msg_types:
                break

        msg1 = CCPMessage(CCPMessage.OPEN_CVPN_CONN,
                0x12345678, 'foo')

        # make sure that we can pack and then recv.
        msg1_buf = msg1.pack()
        (msgs, buf) = CCPMessage.recv(msg1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(msg1))
        assert(buf == '')

        # make sure that we can pack and then recv with a partial
        msg1_buf = msg1.pack() + test_extra
        (msgs, buf) = CCPMessage.recv(msg1_buf)
        assert(len(msgs) == 1)
        assert(str(msgs[0]) == str(msg1))
        assert(buf == test_extra)

        # make sure that we can pack and then recv multiple
        msg1_buf = msg1.pack() * 2
        (msgs, buf) = CCPMessage.recv(msg1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(msg1))
        assert(str(msgs[1]) == str(msg1))
        assert(buf == '')

        # make sure that we can pack and then recv multiple plus a partial
        msg1_buf = (msg1.pack() * 2) + test_extra
        (msgs, buf) = CCPMessage.recv(msg1_buf)
        assert(len(msgs) == 2)
        assert(str(msgs[0]) == str(msg1))
        assert(str(msgs[1]) == str(msg1))
        assert(buf == test_extra)

        # OK, so the basics work.  Now for sanity checks...
        #
        # Change fields and see what happens.

        msg1 = CCPMessage(CCPMessage.OPEN_SOCKS5_CONN,
                0x12345678, 'foo')
        msg1._data = ('f' * CCPMessage.MAX_DATA_LEN) + 'extra'
        msg1_buf = msg1.pack()
        try:
            (msgs, buf) = CCPMessage.recv(msg1_buf)
        except CCPMessageUnpackError, exc:
            print "Bogus data detected"
        else:
            print "Didn't catch too-long data"

        msg1._data = 'foo' # Set back to good
        msg1._version = CCPMessage.PROTOCOL_VERSION + 20
        msg1_buf = msg1.pack()
        try:
            (msgs, buf) = CCPMessage.recv(msg1_buf)
        except CCPMessageUnpackError, exc:
            print "Bogus version detected"
        else:
            print "Didn't catch bogus version"

        msg1._version = CCPMessage.PROTOCOL_VERSION # set back to good

        # TODO: there's no good way to test a bad conn_id, because the packer
        # will always make things that are "OK"

        msg1._msg_type = bogus_msg_type
        msg1_buf = msg1.pack()
        try:
            (msgs, buf) = CCPMessage.recv(msg1_buf)
        except CCPMessageUnpackError, exc:
            print "Bogus msg_type detected"
        else:
            print "Didn't catch bogus msg_type"

        msg1._msg_type = CCPMessage.CLOSE_CONNECTION # make good
        msg1_buf = msg1.pack()
        try:
            (msgs, buf) = CCPMessage.recv(msg1_buf)
        except CCPMessageUnpackError, exc:
            print "False error"
            print exc
        else:
            print "OK"

        return 0

    exit(test_main())



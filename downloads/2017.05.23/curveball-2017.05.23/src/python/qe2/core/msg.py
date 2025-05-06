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
The Qe2 message object and related objects and methods
"""

import struct


class Qe2MsgUnpackError(BaseException):
    """
    Raised if a bad message is detected
    """

    pass

class Qe2Msg(object):
    """
    Implementation of Qe2 protocol message
    """

    # The message header format:
    # 
    # 1 byte: the version number
    #
    # 1 byte: the msg type code
    #
    # 2 bytes: unsigned int, in network byte order, representing
    # the msg payload length (may be zero, if the message is
    # permitted to have a zero-length payload)
    #
    # 2 bytes: unsigned int, in network byte order, representing
    # the length of the chaff in the payload of the message.  If
    # the chaff length is greater to or equal to the length of the
    # payload length, then the entire payload is chaff.
    #
    # If there is chaff, the data is the prefix of the payload and
    # the chaff is the suffix.
    #
    # 16 bytes: the UUID of the quilt for this message
    #
    # 8 bytes: signed int, in network byte order, representing
    # the offset in the stream of the data in the payload (if any)
    #
    # 8 bytes: signed int, in network byte order, representing
    # the highest offset of the *end* of any data message yet sent
    # to this endpoint
    #
    # 8 bytes: signed int, in network byte order, representing
    # the highest offset of the data ready for delivery locally
    #
    # For the last three values, negative numbers are used as
    # sentinels to represent initial, undefined, or illegal values;
    # valid offsets are always >= 0
    #
    HEADER_FMT = '!BBHH16sqqq'

    HEADER_LEN = struct.calcsize(HEADER_FMT)

    OP_DATA = 1
    OP_PING = 2
    OP_CHAN = 3
    OP_HOLE = 4
    OP_HALT = 5
    OP_INIT = 6

    PROTOCOL_VERSION = 0

    MAX_PAYLOAD_LEN = 8192

    OP2STR = {
            OP_DATA : 'data',
            OP_PING : 'ping',
            OP_CHAN : 'chan',
            OP_HOLE : 'hole',
            OP_HALT : 'halt',
            OP_INIT : 'init'
        }

    def __init__(self, opcode, uuid, data, chaff_len,
            send_offset=-1, ack_send=-1, ack_recv=-1):
        """
        ack_send and ack_recv aren't usually known until
        immediately before the message is sent (and may change
        if the message is sent more than once) so by default we
        fill these fields with bogus values.
        """

        self.send_offset = send_offset

        # ack_send is the maximum offset we have sent to the other endpoint
        #
        # ack_recv is the maximum offset that we've been able to deliver
        #
        self.ack_send = ack_send
        self.ack_recv = ack_recv

        self.version = Qe2Msg.PROTOCOL_VERSION

        self.opcode = opcode
        self.uuid = uuid
        self.chaff_len = chaff_len

        if not data:
            self.data = ''
        else:
            self.data = data

        self.payload_len = len(self.data) + chaff_len

        self.check()

    def check(self):
        """
        Sanity-check the values in an instance, to make sure that
        they make sense.

        Note: does not guarantee the validity of the send_offset,
        ack_send, and ack_recv fields, because their validity depends
        on context (the values that are sane now may be wrong later)

        TODO: not a full sanity check yet.
        """

        if self.version != Qe2Msg.PROTOCOL_VERSION:
            raise Qe2MsgUnpackError('bad version [%s]' % str(self.version))

        if self.payload_len > Qe2Msg.MAX_PAYLOAD_LEN:
            raise Qe2MsgUnpackError('payload_len too large [%s]' %
                    str(self.payload_len))

        if self.payload_len < 0:
            raise Qe2MsgUnpackError('payload_len too small [%s]' %
                    str(self.payload_len))

    @staticmethod
    def recv(recv_buffer):
        """
        If there is a prefix of recv_buffer that contains one
        or more complete Qe2Msgs in wire format, parse them,
        remove them from recv_buffer, and return a tuple
        (msgs, remaining_buffer) where msgs is a list of
        Qe2Msg instances created from the parse, and remaining_buffer
        is the un-parsed suffix of recv_buffer
        """

        header_len = Qe2Msg.HEADER_LEN

        msgs = list()
        remaining_buffer = recv_buffer

        while True:
            if len(remaining_buffer) < header_len:
                return (msgs, remaining_buffer)

            # Parse the message, and then see if the payload
            # is complete
            #
            header_bytes = remaining_buffer[:header_len]

            (version, opcode, payload_len, chaff_len, uuid,
                    ack_send, ack_recv, send_offset) = struct.unpack(
                            Qe2Msg.HEADER_FMT, header_bytes)

            # The message we're working on isn't complete, so the
            # parse has failed and we've found everything we're going
            # to find.
            #
            if len(remaining_buffer) < (header_len + payload_len):
                return (msgs, remaining_buffer)

            data_len = payload_len - chaff_len
            if data_len <= 0:
                data = None
            else:
                data = remaining_buffer[header_len:header_len + data_len]

            # Add more sanity checks here: version
            if version != Qe2Msg.PROTOCOL_VERSION:
                raise Qe2MsgUnpackError('bad version %s' % str(version))

            if opcode == Qe2Msg.OP_DATA:
                new_msg = Qe2DataMsg(uuid, data, chaff_len,
                        send_offset, ack_send, ack_recv)
            elif opcode == Qe2Msg.OP_HOLE:
                (hole_base, hole_len) = struct.unpack('!QQ', data)

                new_msg = Qe2HoleMsg(uuid, (hole_base, hole_len), chaff_len,
                        send_offset, ack_send, ack_recv)
            else:
                # Punt: we don't have a special object of this msg.
                #
                new_msg = Qe2Msg(opcode, uuid, data, chaff_len,
                        send_offset, ack_send, ack_recv)
            msgs.append(new_msg)

            remaining_buffer = remaining_buffer[header_len + payload_len:]

    def __str__(self):
        """
        Create a human-readable version of this instance
        """

        if self.opcode in Qe2Msg.OP2STR:
            opcode = Qe2Msg.OP2STR[self.opcode]
        else:
            opcode = str(self.opcode)

        txt = 'Qe2Msg version %d opcode %s ' % (self.version, opcode)
        txt += 'payload_len %u chaff_len %u ' % (
                self.payload_len, self.chaff_len)
        txt += 'send_offset %d ack_send %d ack_recv %d' % (
                self.send_offset, self.ack_send, self.ack_recv)

        return txt

    def pack(self, send_offset=-1, ack_send=-1, ack_recv=-1):
        """
        Create a string containing the wire representation of this Qe2Msg
        instance.

        Does no error checking for sanity.
        """

        # if and of send_offset, ack_send, or ack_recv are not provided
        # (or are -1) then use instance values.
        #
        if send_offset == -1:
            send_offset = self.send_offset

        if ack_send == -1:
            ack_send = self.ack_send

        if ack_recv == -1:
            ack_recv = self.ack_recv

        header = struct.pack(Qe2Msg.HEADER_FMT,
                self.version, self.opcode, self.payload_len, self.chaff_len,
                self.uuid, ack_send, ack_recv, send_offset)

        chaff_len = self.chaff_len

        if chaff_len > self.payload_len:
            chaff_len = self.payload_len

        if chaff_len > 0:
            chaff = '0' * chaff_len
        else:
            chaff = ''

        msg = header + self.data + chaff

        return msg

    def send(self, sock, send_offset=-1, ack_send=-1, ack_recv=-1):
        """
        Pack this instance and send it via the given sock
        """
        return sock.send(self.pack(send_offset=send_offset,
                ack_send=ack_send, ack_recv=ack_recv))


class Qe2DataMsg(Qe2Msg):
    """
    A data message
    """

    def __init__(self, uuid, data, chaff_len,
            send_offset=-1, ack_send=-1, ack_recv=-1):

        Qe2Msg.__init__(self, self.OP_DATA, uuid, data, chaff_len,
                send_offset, ack_send, ack_recv)


class Qe2HoleMsg(Qe2Msg):
    """
    A hole message, which signals to the recipient that the sender
    is waiting for data to fill the given hole.
    """

    def __init__(self, uuid, hole, chaff_len,
            send_offset=-1, ack_send=-1, ack_recv=-1):

        hole_str = struct.pack('!QQ', hole[0], hole[1])
        self.hole = hole

        Qe2Msg.__init__(self, self.OP_HOLE, uuid, hole_str, chaff_len,
                send_offset, ack_send, ack_recv)

    def __str__(self):
        return Qe2Msg.__str__(self) + ' hole ' + str(self.hole)


class Qe2PingMsg(Qe2Msg):
    """
    A ping message, used to acknowledge data and indicate that the
    channel is still alive

    A ping message is like a data message without any data and
    with a bogus (and ignored) send_offset
    """

    def __init__(self, uuid, chaff_len, ack_send=-1, ack_recv=-1):

        Qe2Msg.__init__(self, self.OP_PING, uuid, '', chaff_len,
                -1, ack_send, ack_recv)

class Qe2ChanMsg(Qe2Msg):
    """
    A channel setup message, used to request the establishment of a new
    channel with the given uuid.

    This is intended to be used to carry arbitrary channel information,
    but none of the baseline quilting channels have any per-instance
    initialization parameters, so there's no data in the payload
    """

    def __init__(self, uuid, chaff_len=0, ack_send=-1, ack_recv=-1):

        Qe2Msg.__init__(self, self.OP_CHAN, uuid, '', chaff_len,
                -1, ack_send, ack_recv)

class Qe2HaltMsg(Qe2Msg):
    """
    A message that tells the recipent that the quilt with the given uuid
    is no longer valid, and must be abandoned
    """

    def __init__(self, uuid, chaff_len=0, ack_send=-1, ack_recv=-1):

        Qe2Msg.__init__(self, self.OP_HALT, uuid, '', chaff_len,
                -1, ack_send, ack_recv)


if __name__ == '__main__':
    def test_main():

        msg1 = Qe2Msg(0, '1' * 16, 'a', 10)
        msg2 = Qe2Msg(0, '1' * 16, 'bb', 10)
        msg3 = Qe2Msg(0, '1' * 16, 'ccc', 10)

        p_msg1 = msg1.pack()
        p_msg2 = msg2.pack()
        p_msg3 = msg3.pack()

        print len(p_msg1)
        print len(p_msg2)
        print len(p_msg3)

        buf = msg1.pack() + msg2.pack() + msg3.pack()

        (msgs, remaining) = Qe2Msg.recv(buf)

        print 'msgs[0] = [%s][%s]' % (str(msgs[0]), msgs[0].data)
        print 'msgs[1] = [%s][%s]' % (str(msgs[1]), msgs[1].data)
        print 'msgs[2] = [%s][%s]' % (str(msgs[2]), msgs[2].data)

    test_main()

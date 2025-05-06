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
Channel endpoint logic
"""

import time

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet.task import LoopingCall
import twisted.internet.endpoints as endpoints

from qe2.core.log import QE2LOG
from qe2.core.msg import Qe2ChanMsg
from qe2.core.msg import Qe2DataMsg
from qe2.core.msg import Qe2PingMsg
from qe2.core.msg import Qe2Msg

class Qe2Channel(object):
    """
    Implements the server side of the Qe2 connection protocol
    """

    def __init__(self, endpoint, lifespan=-1):
        self.endpoint = endpoint
        self.transport = None
        self.looper = None

        # members used for the heuristics for when this channel
        # should shut itself down.  The pusher method is responsible
        # for updating the byte and message counts (as necessary).
        #
        # This should be updated by the connect() method.
        #
        self.connect_time = time.time()

        # TODO: max_idle_time could be a parameter
        #
        self.max_idle_time = 0.5

        # Intentionally tiny for debugging purposes.  Subclasses
        # should override
        #
        self.max_msg_size = Qe2Msg.MAX_PAYLOAD_LEN

        # We don't set the next_ping_time to something meaningful
        # until we're connected
        #
        self.next_ping_time = -1

        # don't bunch up hole fill requests: force a pause of at
        # least hole_request_interval between requests
        #
        self.last_hole_request_time = 0
        self.hole_request_interval = 0.05

        # similarly, don't bunch up hole fill responses: force a
        # pause of at least hole_response_interval between responses
        #
        self.last_hole_response_time = 0
        self.hole_response_interval = 0.05

        # When the lifespan of the channel has exceeded self.max_time,
        # then it is time for the channel to close.
        #
        # There may be other metrics and heuristics used by other channels.
        # The convention is that any max_* values set to -1 are ignored.
        #
        self.max_time = lifespan

        # The current hole that the remote endpoint has asked us to fill.
        # and we're working on filling. (the remote endpoint might have
        # sent us many requests for hole filling, but we only work on
        # one at a time)
        #
        self.remote_fill_msgs = None
        self.remote_holes_filled = set()

    def connect(self):
        """
        Connect with the other end of this channel.

        Intended to be overridden.  See Qe2SocketClientChannel
        for an example.
        """

        pass

    def disconnect(self):
        """
        Disconnect from the other end of the channel, and tear
        down any related structures/processes/etc

        Intended to be extended, but all subclasses should invoke this
        to take care of cleaning up the connection and the looper.
        """

        if self.looper:
            self.looper.stop()
            self.looper = None

        if self.transport:
            self.transport.loseConnection()
            self.transport = None

    def connection_failed(self, reason):
        """
        Couldn't connect, or lost the connection

        This will usually be subclassed, because how to react to failure
        depends on details of the connection.
        """

        QE2LOG.warn('Qe2Channel.connection_failed(): %s', str(reason))

        # TODO NEED TO RETRY

    def set_looper(self, looper):
        """
        Provide this instance with a reference to the LoopingCall
        instance that invokes its pusher, and return the reference.

        This provides a way for the pusher function to modify the
        LoopingCall (for example to change the interval).
        """

        self.looper = looper
        return looper

    def is_connected(self):
        """
        Are we connected to the other side yet?

        May be overridden.
        """

        return self.transport

    def get_transport(self):
        """
        Return a reference to the transport to write to
        """

        return self.transport

    def should_close(self):
        """
        Return True if the channel should close (according to
        whatever heuristics are used by this channel).

        This is arbitrary and is intended to be overridden.

        The default behavior is to close the channel after it
        has been open for max_time seconds, if max_time is greater
        than or equal to 0.  If max_time is -1, then the channel
        is immortal.

        TODO: if the endpoint is lost for any reason, the
        channel should close.  We're not checking that now.
        """

        if self.max_time >= 0:
            # print 'ELAPSED %f' % (time.time() - self.connect_time)
            if (time.time() - self.connect_time) >= self.max_time:
                return True

        return False

    def create_ping_msg(self, msgs):
        """
        Construct and return a ping message, if appropriate,
        or None if it is not appropriate to send a ping.

        We usually don't want send a ping at every opportunity,
        because the information is redundant if another message
        has been sent recently.  Therefore the default is to only
        send a ping if the current time is later than
        self.next_ping_time and we don't have anything else to send
        (msgs is empty).

        self.next_ping_time is updated whenever we send anything,
        so this only happens if we haven't sent anything
        for self.max_idle_time seconds.
        """

        if len(msgs) > 0:
            return None
        elif time.time() < self.next_ping_time:
            return None

        ping_msg = Qe2PingMsg(self.endpoint.uuid, 0)
        return ping_msg

    def create_data_msg(self, min_data_len, max_data_len):
        """
        Create and return a data message for data at the head
        of pending_out, if any, with the given minimum and maximum
        size.

        If there is no data pending, then chaff is added to bring
        the message up to the minimum payload size.

        Find the current offset of the head of pending_out
        and then attempt to dataDequeue some pending_out data.
        avail = the number of bytes available

        Only take as much as makes sense given whatever
        protocol the channel uses.  Never grab more than
        you can fit into a single Qe2Msg.
        """

        endpoint = self.endpoint

        data_len = max_data_len
        chaff_len = 0

        # Note that endpoint.next_offset and endpoint.ack_send
        # are updated here to reflect the state of the endpoint.
        #
        avail = endpoint.pending_out.last - endpoint.next_offset
        if avail < data_len:
            data_len = avail

        if data_len < min_data_len:
            chaff_len = min_data_len - data_len

        if data_len > 0:
            data = endpoint.pending_out.peek(
                    endpoint.next_offset,
                    endpoint.next_offset + data_len)
        else:
            data = ''

        if (chaff_len == 0) and (data_len == 0):
            return None
        else:
            msg = Qe2DataMsg(endpoint.uuid, data, chaff_len,
                    endpoint.next_offset)

            endpoint.next_offset += len(data)
            endpoint.ack_send = endpoint.next_offset - 1

            return msg

    def pusher(self):
        """
        Example of a push worker, invoked by a looping call,
        to push data from the pending_out to the channel server.
        This is the heart of a channel, and where the customization
        for each channel takes place.

        This is a very simple pusher method that can be invoked by a
        LoopingCall.  It is fully functional in a basic way, but is
        intended to be overridden in subclasses.

        The basic mechanism is to dequeue any pending data from
        pending_out, and send it in a data message.  If there is
        no pending data, it optionally can send a chaff message,
        as this example does.  A pusher can send any combination
        of data and chaff necessary to shape the traffic as
        requested.

        The pusher can also service hole requests (requests from
        the opposite endpoint of the channel for missing data),
        or send hole requests if any holes have been detected
        locally.

        The general form of a simple pusher is:

        1.  Return immediately if the channel is not available.
            (If we're not connected yet, then don't try to send
            any data)

        2.  If it is time for this channel to close (because it
            has been open too long, or has sent the desired amount
            of traffic, or some other heuristic for deciding when
            a channel should be closed) then close it and return.

        3.  Do some combination of the following:

            a) Dequeue some data from pending_out.  Note the current offset.
                Make a data message from the queue.

                Note that when you dequeue data from pending_out, you
                MUST also update two fields in the endpoint in order to
                mark that the data is in the process of being sent:

                self.endpoint.next_offset - the next offset to dequeue

                self.endpoint.ack_send    - the highest offset of any data
                        sent to the opposite endpoint so far

                Right now, ack_send is always next_offset - 1, and it's
                possible that they will be combined in the future unless
                we want to get fancy with out-of-order messages.

                It is typical to avoid asking for more data than can
                fit in one message, but this is not required.  Multiple
                data messages can be composed in a single push.

            b) If there is no data, or not enough data to satisfy
                the traffic shaping requirements (if any) then
                pad the data message with chaff and/or create one
                or more chaff messages.

            c) Create a hole fill request message

            d) Create a data message that satisfies a hole request

            As each message is created, it is added to a list.

        4.  Pack each Qe2Msg in the message list, and place the result
            in a buffer, and write the buffer to the channel's transport.

            Note that we delay packing the message list until the end
            so we can get the most up-to-date metadata.

            If sending more than one Qe2Msg, it can be important
            to serialize them into a single write to avoid
            potential synchronization issues.  Doing one large write
            is more efficient than several of small writes, unless small
            writes are required for the channel traffic shaping (in which
            case you should have dequeued less data in step #2a, or
            rewritten the pusher in order to write less data in each
            invocation).

        """

        now = time.time()

        if self.last_hole_response_time == 0:
            self.last_hole_response_time = now
        if self.last_hole_request_time == 0:
            self.last_hole_request_time = now

        # We'll always send messages with a data length of msg_data_size,
        # even if we don't have any data (and need to fill it with chaff)
        #
        msg_data_size = self.max_msg_size

        if self.should_close():
            self.disconnect()
            return

        # If we're not connected yet, then we can't push data
        # anywhere.  Quietly return.
        #
        if not self.is_connected():
            # print 'CHANNEL NOT CONNECTED YET'
            return

        endpoint = self.endpoint

        # msgs_to_send is the list of message instances that
        # we want to send.  We don't pack these messages
        # until we're ready to send them.
        #
        msgs_to_send = list()

        data_msg = self.create_data_msg(0, msg_data_size)
        if data_msg:
            msgs_to_send.append(data_msg)

        # Do we want to send more chaff?
        # This is a fine place to add chaff.

        # If there's a remote hole to fill, or we're already in
        # the midst of filling a remote hole, add fill msgs to the list
        #
        # We should prefer to send fill data instead of new data because
        # sending new data when there are already holes can create
        # or extend holes, causing more requests.
        #

        """
        This doesn't seem to work yet
        if not self.remote_fill_msgs:
            hole = endpoint.next_remote_hole()
            if hole and (not hole in self.remote_holes_filled):
                self.remote_holes_filled.add(hole)
                self.remote_fill_msgs = endpoint.create_hole_msg_list(
                        hole[0], hole[1], msg_data_size)

        if self.remote_fill_msgs:
            fill_res = self.remote_fill_msgs.pop()
            msgs_to_send.append(fill_res)
        """

        if (now - self.last_hole_response_time) > self.hole_response_interval:
            fill_res = endpoint.fill_remote_hole()
            if fill_res:
                msgs_to_send.append(fill_res)
                self.last_hole_response_time = now
                QE2LOG.info('responding to a hole fill')

        # Are there any holes that make us stuck, waiting to be filled?
        # Ask the remote endpoint to fill them.
        #
        # Heuristic: don't ask for a hole request until at least
        # self.hole_request_interval seconds have elapsed since the
        # last request.  Give the channel a chance to fill the hole
        # before re-requesting
        #
        if (now - self.last_hole_request_time) > self.hole_request_interval:
            fill_req = endpoint.request_hole_fill()
            if fill_req:
                # print 'PENDING SEGMENTS: %s' % str(endpoint.pending_in.segments)
                msgs_to_send.append(fill_req)
                self.last_hole_request_time = now
                QE2LOG.info('requesting a hole fill')

        # Do we want to send a ping?
        # A ping will tell the endpoint our state.
        #
        ping_msg = self.create_ping_msg(msgs_to_send)
        if ping_msg:
            # print '>>>>>>>>>>> SENDING PING'
            msgs_to_send.append(ping_msg)

        # If we created any messages, then pack them.  If the result
        # is a non-empty string of packed data, then write it to the
        # transport.
        #
        packed = ''
        for msg in msgs_to_send:

            msg.ack_send = endpoint.ack_send
            msg.ack_recv = endpoint.ack_recv

            QE2LOG.debug('sending %s', str(msg))

            packed += msg.pack()

        if packed:
            # If we're sending anything, then update self.next_ping_time
            #
            self.next_ping_time = time.time() + self.max_idle_time

            transport = self.get_transport()
            transport.write(packed)

            QE2LOG.debug('ack_send is %d', endpoint.ack_send)


class Qe2ChannelWorker(Protocol):

    def __init__(self):
        # print 'Qe2ChannelWorker.__init__()'

        self.recv_buf = ''

    def connectionFailed(self):
        """
        twisted connectionFailed
        """

        QE2LOG.warn('Qe2ChannelWorker: connectionFailed')

    def connectionMade(self):
        """
        twisted connectionMade
        """

        # print 'Qe2ChannelWorker: connectionMade'

        # Let our wrapper Qe2Channel know that it has a transport
        #
        self.factory.qe2chan.transport = self.transport

        # Immediately send a chan message to establish that
        # this is a new connection
        #
        chan_setup_msg = Qe2ChanMsg(self.factory.qe2chan.endpoint.uuid)
        self.transport.write(chan_setup_msg.pack())

    def dataReceived(self, data):
        """
        Receive data from the connection.

        The data is assumed to be a sequence of serialized
        Qe2Msg instances.  Reconstruct the instances, and then
        process the messages.
        """

        # print 'Qe2ChannelWorker: dataReceived LEN %d' % len(data)

        conn = self.factory.qe2chan
        endpoint = conn.endpoint

        self.recv_buf += data

        # print 'recv_buf len [%d]' % len(self.recv_buf)

        (msgs, self.recv_buf) = Qe2Msg.recv(self.recv_buf)

        endpoint.process_msgs(msgs)

    def connectionLost(self, reason=None):
        """
        twisted connectionLost
        """

        QE2LOG.debug('Qe2ChannelWorker: connectionLost')
        self.factory.qe2chan.disconnect()


class Qe2SocketClientChannel(Qe2Channel):
    """
    A client-side Qe2Channel that connects to an ordinary socket
    """

    def __init__(self, endpoint, lifespan=-1):
        Qe2Channel.__init__(self, endpoint, lifespan=lifespan)

        self.svr_host = endpoint.svr_host
        self.svr_port = endpoint.svr_port

    def connect(self):
        """
        Connect with the other end of this channel.

        This method is usually overloaded by a subclass.
        This implementation is only meant for TCP sockets
        (using Twisted).
        """

        # print 'Qe2SocketClientChannel.connect'

        self.factory = Factory()
        self.factory.protocol = Qe2ChannelWorker
        self.factory.qe2chan = self

        # print '%s %s' % (str(self.svr_host), str(self.svr_port))

        endpoint = endpoints.TCP4ClientEndpoint(reactor,
                self.svr_host, self.svr_port, timeout=10)
        connection = endpoint.connect(self.factory)
        connection.addErrback(self.connection_failed)


class Qe2SocketServerChannel(Qe2Channel):
    """
    A server-side Qe2Channel that uses a twisted transport as its channel
    """

    def __init__(self, transport, endpoint):
        Qe2Channel.__init__(self, endpoint, lifespan=-1)

        self.transport = transport

        looper = LoopingCall(self.pusher)
        self.looper = looper

        looper.start(0.01)

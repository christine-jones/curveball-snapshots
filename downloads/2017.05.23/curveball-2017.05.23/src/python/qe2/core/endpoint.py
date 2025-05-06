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
Base class for Quilt endpoints
"""

from twisted.internet import reactor

from qe2.core.assembler import Qe2Assembler
from qe2.core.log import QE2LOG
from qe2.core.msg import Qe2DataMsg
from qe2.core.msg import Qe2HoleMsg
from qe2.core.msg import Qe2Msg
from qe2.core.queue import FastByteQueue


class Qe2Endpoint(object):
    """
    Qe2 Quilt endpoint base class
    """

    def __init__(self):

        # pending_out represents the queue of bytes that are waiting
        # to be sent from this endpoint to the matching endpoint via
        # some channel.  This is implemented by an instance of
        # ByteQueue, which permits dequeued data to be accessed until
        # it is flushed.  This is important because when data is
        # dequeued, it's sent on a lossy channel and so we might need
        # to send it again (and again...).
        #
        self.pending_out = FastByteQueue()

        # The next offset of data to send (in the absence of holes).
        #
        self.next_offset = 0

        # pending_in represents the stream of bytes that have arrived
        # from the matching endpoint, via some channel.  The bytes might
        # arrive in an arbitrary order, so we use an assembler to make
        # sure they are delivered in order.
        #
        self.pending_in = Qe2Assembler()

        # A set of all of the "bottoms" connected to this endpoint.
        # Each bottom is the container for a channel.
        #
        self.bottoms = set()

        # A set of holes that the other endpoint has told us about.
        # We'll need to fill them eventually (if they're not bogus
        # or short-lived).
        #
        self.remote_holes = set()

        # A set of holes that we want to tell the other endpoint about.
        # We can't proceed until these holes are filled by some means
        #
        self.local_holes = set()

        # ack_send is the highest value data offset that we've sent.
        # When we send a message at self.next_offset, this is set to
        # self.next_offset + len(data).
        #
        self.ack_send = -1

        # ack_recv is the highest value data offset that we've been able
        # to deliver to the local top/app via pending_to_app (ack_recv
        # isn't really the ideal name for this)
        #
        self.ack_recv = -1

        self.remote_ack_send = -1
        self.remote_ack_recv = -1

        # self.uuid is the quilt ID chosen by the client, and is used
        # to label all messages associated with the quilt
        #
        # self.server_quilt_uuid is a UUID chosen by the server to identify
        # its end of the quilt.  This identifier is only used to validate
        # that each client for a given quilt is connecting to the same
        # server (i.e., if the server crashes and restarts, then the
        # server_quilt_uuid will change and the client will be able to
        # distinguish between a channel disruption and server disruption)
        #
        self.uuid = None
        self.server_quilt_uuid = None

        # The ChannelManager that creates channels used by this
        # endpoint.  Used by the endpoint to shut down all channels
        # when an error occurs, etc.
        #
        # Only client endpoints have channel managers right now,
        # but instead of subclassing Endpoint just for this, we
        # we pretend servers have them too.  Someday they might.
        #
        self.chanman = None

    def register_chanman(self, chanman):
        """
        Register the channel manager used by this endpoint

        It is an error for there to be more than one chanman per endpoint,
        or to change the chanman after it is established, so we raise an
        exception if this method is used more than once to set a non-None
        chanman per endpoint.
        """

        assert(self.chanman == None)

        self.chanman = chanman

    def send(self, data):
        """
        Non-blocking send: enqueues the data, but doesn't
        necessarily push it out

        subclasses should nudge any ready channels to see if they
        are ready to accept any data
        """

        self.pending_out.enq(data)

    def recv(self, wanted=-1):
        """
        Non-blocking recv: return whatever data, if any, is
        immediately available from pending_in
        """

        return self.pending_in.dequeue(wanted_len=wanted)

    def first_missing(self):
        """
        Return the starting offset and length of the first "hole" in
        the pending_in assembler.  This is used in the acknowledgement
        messages to tell the other endpoint what info we don't yet have.
        """

        return self.pending_in.first_missing()

    def add_bottom(self, bottom):
        """
        Add a *Bottom instance to this endpoint
        """

        self.bottoms.add(bottom)

    def del_bottom(self, bottom):
        """
        Remove a *Bottom instance from this endpoint

        If the instance isn't part of this endpoint, print a diagnostic
        and swallow the error
        """

        try:
            self.bottoms.remove(bottom)
        except KeyError, exc:
            QE2LOG.error('Qe2Endpoint.del_bottom: missing bottom')

    def deliver(self, offset, data):
        """
        Deliver bytes that arrive from a channel,
        by adding them to the assembler
        """

        # print 'Qe2Endpoint.deliver'
        self.pending_in.add_segment(offset, data)

    def pending_to_app(self):
        """
        If there is pending data that is ready to forward to the top/app,
        then send some of it along (or all of it, if there's not much).

        Note that we can end up in livelock if we just send everything
        through as quickly as possible.  For this reason, we only send
        a fixed amount through at a time.

        TODO: we need a real throttling mechanism.
        """

        if ((not self.top) or (not self.top.app_connected)):
            QE2LOG.info('Qe2Endpoint.pending_to_app: app not connected')
            return

        ready_len = self.pending_in.data_ready()
        if ready_len > 0:
            # FIXME: this is a mistake if there's too much ready_len
            # because we could blow out the transport if it can't
            # keep up.  What we need to do is bite off what we can
            # and have a looping call that takes the rest.
            #
            data = self.pending_in.dequeue(ready_len)
            QE2LOG.debug('Qe2Channel.pending_to_app: data %d', len(data))

            # Now that we've delivered this data, we won't ask for
            # it again
            #
            self.ack_recv += len(data)

            self.top.transport.write(data)
        else:
            # print 'Qe2Channel.pending_to_app: NO data'
            (hole_base, hole_len) = self.pending_in.first_missing()

            if hole_len != -1:
                QE2LOG.debug('NEED TO FILL HOLE [base %d len %d]',
                        hole_base, hole_len)
                self.add_local_hole(hole_base, hole_base + hole_len - 1)
            else:
                # print 'pending_to_app: not missing anything'
                pass

        QE2LOG.debug('RECV THROUGH %d', self.ack_recv)

    def add_local_hole(self, hole_start, hole_end):
        """
        Record that we have a hole.

        Holes are filled according to channel heuristics, but
        recorded centrally.
        """

        # print '<<<< ADDING LOCAL HOLE'
        self.local_holes.add((hole_start, hole_end))
        self.prune_local_holes()

    def prune_local_holes(self):
        """
        Remove any local holes that end before the current
        offset and truncate any that are no longer completely
        "missing".  The coalesce any holes that start at
        the same offset.
        """

        (first_offset, first_len) = self.first_missing()

        new_set = set()

        for hole in self.local_holes:
            if hole[0] >= first_offset:
                new_set.add(hole)
            elif (hole[0] < first_offset) and (hole[1] >= first_offset):
                new_set.add((first_offset, hole[1]))

        new_set = self.prune_prefix_holes(new_set)

        if new_set:
            QE2LOG.debug('LOCAL HOLES: %s', str(sorted(new_set)))

        self.local_holes = new_set

    def add_remote_hole(self, new_hole_start, new_hole_end):
        """
        Record that the opposite endpoint has notified us that
        there is an apparent hole in their received data (by
        sending us a Qe2HoleMsg).

        Note that we don't just add the hole into the set verbatim;
        we try to find other holes that can be combined with other
        holes.  (it may, in fact, be better to combine two small holes
        that are separated by a non-hole in order to reduce the number
        of hole-fill messages... but we don't do that right now because
        the situation doesn't appear to happen in practice)

        The most common case is that a hole is "extended" because
        we find out that we're missing more data than we thought.
        This is the most important case to handle, rather than
        overlapping holes.

        Holes are filled according to channel heuristics, but
        recorded centrally.
        """

        QE2LOG.info('add_remote_hole: adding hole (%d %d)',
                new_hole_start, new_hole_end)

        for (old_hole_start, old_hole_end) in sorted(self.remote_holes):

            # The most common case is that a hole is "extended"
            # because we find out that we're missing more data than
            # we thought
            #
            # Another case is when a new hole fits entirely within
            # an existing hole, and therefore the new hole can be ignored
            #
            if ((old_hole_start == new_hole_start) and
                    (old_hole_end < new_hole_end)):
                self.remote_holes.discard((old_hole_start, old_hole_end))
                self.remote_holes.add((old_hole_start, new_hole_end))
                return
            elif ((old_hole_start <= new_hole_start) and
                    (old_hole_end >= new_hole_end)):
                return

        self.remote_holes.add((new_hole_start, new_hole_end))

    def request_hole_fill(self):
        """
        If we're stuck on a hole, make a request for it
        to be filled.  Returns None if we're not stuck.
        """

        holes = self.pending_in.find_holes()

        # QE2LOG.info('my find_holes(): %s', str(holes))

        if not holes:
            return None

        if len(holes) == 1:
            if self.remote_ack_send > holes[0][0]:
                hole_start = holes[0][0]
                hole_end = self.remote_ack_send
            else:
                return None
        else:
            (hole_start, hole_end) = holes[0]


        """
        QE2LOG.warn('RAW HOLES: %s', str(

        self.prune_local_holes()

        if not self.local_holes:
            return None

        QE2LOG.info('MY HOLES %s', str(sorted(self.local_holes)))

        (hole_start, hole_end) = sorted(self.local_holes)[0]
        # self.local_holes.discard((hole_start, hole_end))
        """

        QE2LOG.debug('request_hole_fill: need fill for [%d %d]',
                hole_start, hole_end)

        msg = Qe2HoleMsg(self.uuid, (hole_start, 1 + hole_end - hole_start),
                0, 0, ack_send=self.ack_send, ack_recv=self.ack_recv)

        return msg

    @staticmethod
    def prune_prefix_holes(holes):
        """
        Prune away holes that are prefixes of other holes
        """

        remaining_holes = set()
        prev_hole = None

        for (hole_start, hole_end) in sorted(holes):
            remaining_holes.add((hole_start, hole_end))

            if prev_hole == None:
                prev_hole = (hole_start, hole_end)
                continue

            if (hole_start == prev_hole[0]) and (hole_end > prev_hole[1]):
                remaining_holes.discard(prev_hole)
                prev_hole = ((hole_start, hole_end))

        return remaining_holes

    def prune_remote_holes(self):
        """
        Remove any holes that were reported by the opposite endpoint
        that have already filled (according to ack_recvs reported by that
        endpoint).  These holes might have been filled by messages
        in-flight.
        """

        remaining_holes = set()

        for (hole_start, hole_end) in sorted(self.remote_holes):

            # If the hole_end is after the remote_ack_recv, then
            # this hole has an unfilled component (from what we can
            # tell)
            #
            if hole_end > self.remote_ack_recv:

                # If the start of the hole is prior to self.remote_ack_recv,
                # adjust the hole_start so we don't re-send data that
                # the opposite endpoint already has.
                #
                if hole_start <= self.remote_ack_recv:
                    hole_start = self.remote_ack_recv + 1

                remaining_holes.add((hole_start, hole_end))

        self.remote_holes = self.prune_prefix_holes(remaining_holes)

        if self.remote_holes:
            QE2LOG.debug('REMOTE HOLES: %s', str(self.remote_holes))

        return self.remote_holes

    def next_remote_hole(self):
        """
        Return the start and end of the next hole, or None if
        there is no next hole
        """

        self.prune_remote_holes()
        if not self.remote_holes:
            return None

        (hole_start, hole_end) = sorted(self.remote_holes)[0]

        return (hole_start, hole_end)

    def create_hole_msg_list(self, hole_start, hole_end, max_msg_size):
        """
        Create a list of messages that can be used to fill
        the "oldest" hole that the remote needs us to fill
        """

        content = self.pending_out.peek(hole_start, hole_end + 1)

        QE2LOG.warn('creating descriptor for hole [%d %d]',
                hole_start, hole_end)
        QE2LOG.warn('hole length %d content length %d',
                1 + hole_end - hole_start, len(content))

        # This is not very efficient in terms of memory or CPU,
        # but it's not the bottleneck.
        #
        msgs = list()
        while content:
            content_prefix = content[:max_msg_size]
            content = content[max_msg_size:]

            msg = Qe2DataMsg(self.uuid, content_prefix, 0,
                        send_offset=hole_start)
            hole_start += len(content_prefix)

            msgs.append(msg)

        # reverse the list to make it easier to pop off the msgs.
        #
        msgs.reverse()

        return msgs

    def fill_remote_hole(self):
        """
        Select the "oldest" hole from remote_holes,
        and create a Qe2DataMsg to fill it.

        Return None if there is no hole to fill.
        """

        self.prune_remote_holes()

        if not self.remote_holes:
            return None

        (hole_start, hole_end) = sorted(self.remote_holes)[0]

        # If the hole is too large to stuff into one message,
        # put as much as we can
        #
        if (1 + hole_end - hole_start) > Qe2Msg.MAX_PAYLOAD_LEN:
            hole_end = hole_start + Qe2Msg.MAX_PAYLOAD_LEN - 1

        QE2LOG.debug('fill_remote_hole: filling [%d %d]',
                hole_start, hole_end)

        try:
            filler = self.pending_out.peek(hole_start, hole_end + 1)
            if filler:
                # print 'fill_remote_hole: filler is [%s]' % filler

                hole_msg = Qe2DataMsg(self.uuid, filler, 0,
                        send_offset=hole_start)
                return hole_msg
            else:
                QE2LOG.warn('fill_remote_hole: filler [%d, %d] not found',
                        hole_start, hole_end)
                return None
        except BaseException, exc:
            QE2LOG.warn('fill_remote_hole: exception [%s]', str(exc))
            return None

    def handle_init(self, msg):
        """
        Handle receipt of a OP_INIT msg.

        Note that it is an error for this to be received
        by a server, so QuiltServers should subclass this method

        The server_quilt_uuid is the uuid assigned to this
        quilt by the server.  If this is the first OP_INIT
        we've gotten from the server, then remember make note
        of it.  If it's not the first OP_INIT, then check that
        the server_quilt_uuid matches previous server_quilt_uuids,
        and drop the connection if it does not.
        """

        server_quilt_uuid = msg.data[:16]

        if self.server_quilt_uuid == None:
            QE2LOG.info('got server_quilt_uuid %s',
                    server_quilt_uuid.encode('hex'))
            self.server_quilt_uuid = server_quilt_uuid
        elif self.server_quilt_uuid != server_quilt_uuid:
            QE2LOG.warn('server_quilt_uuid mismatch: expected %s got %s',
                    self.server_quilt_uuid.encode('hex'),
                    server_quilt_uuid.encode('hex'))
            QE2LOG.info('dropping quilt')

            # If there is a channel manager, ask it to stop
            # all channels
            #
            if self.chanman:
                QE2LOG.warn('stopping all connections')
                self.chanman.stop_all()
            else:
                QE2LOG.error('no chanman?')

            # reactor.callLater(2, reactor.stop)
            reactor.stop()

    def process_msgs(self, msgs):
        """
        Process messages received by a channel
        """

        max_offset = -1
        delivered = False

        old_remote_ack_recv = self.remote_ack_recv

        for msg in msgs:
            QE2LOG.debug('RECEIVE MSG %s', str(msg))

            # update max_offset and remote_ack_recv, no
            # matter what the message type is
            #
            if max_offset < msg.ack_send:
                max_offset = msg.ack_send

            if self.remote_ack_recv < msg.ack_recv:
                self.remote_ack_recv = msg.ack_recv
            if self.remote_ack_send < msg.ack_send:
                self.remote_ack_send = msg.ack_send

            if msg.opcode == Qe2Msg.OP_DATA:
                if len(msg.data) > 0:
                    self.deliver(msg.send_offset, msg.data)
                    delivered = True

            elif msg.opcode == Qe2Msg.OP_PING:
                pass
            elif msg.opcode == Qe2Msg.OP_HOLE:

                if self.remote_ack_recv > msg.hole[0]:
                    QE2LOG.info('UNEXPECTED hole start before remote_ack_recv')

                self.add_remote_hole(
                        msg.hole[0], msg.hole[0] + msg.hole[1] - 1)
            elif msg.opcode == Qe2Msg.OP_CHAN:
                QE2LOG.info('got OP_CHAN message')
                pass
            elif msg.opcode == Qe2Msg.OP_HALT:
                # TODO: this should close down the quilt (not just
                # one particular channel)
                #
                QE2LOG.info('got OP_HALT message')
            elif msg.opcode == Qe2Msg.OP_INIT:
                self.handle_init(msg)
            else:
                QE2LOG.error('UNHANDLED msg %d', msg.opcode)

        # If this sequence of msgs included delivered data, then
        # see if there's anything to push to the app
        #
        if delivered:
            self.pending_to_app()

        if max_offset > self.ack_recv:
            QE2LOG.info('max_offset %d > self.ack_rev %d: something missing',
                    max_offset, self.ack_recv)
            self.add_local_hole(self.ack_recv + 1, max_offset)
            QE2LOG.debug('LOCAL holes %s', str(sorted(self.local_holes)))

        # We've gotten acknowledgment from the remote endpoint
        # for additional data.  Throw away our old copy.
        #
        # TODO: it is much more efficient to delete larger chunks
        # periodically rather than small chunks constantly.
        #
        if old_remote_ack_recv < self.remote_ack_recv:
            self.pending_out.discard(
                    self.remote_ack_recv - old_remote_ack_recv)


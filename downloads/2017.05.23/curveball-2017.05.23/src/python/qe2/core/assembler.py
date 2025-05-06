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
Reassemble a stream that has been broken into segments,
and track what has been delivered.

This would be fairly straightforward if all the segments were
the same size and didn't overlap, etc, but there are no such
guarantees and we need to be prepared for almost anything.

The semantics of overlapping or repeated segments is that the
first bytes to arrive are the bytes that are delivered.

This implementation is designed to be robust, but not
particularly efficient.  Time permitting, we'll come back
and add cleverness, but the first priority is to get something
that correctly handles strange input.

For the sake of trading off efficiency for simplicity,
a segment is represented as a list of length three:

    [ first_offset, last_offset, segment_data ]

(last_offset is implicitly first_offset + len(segment_data) - 1,
but it's convenient to avoid recomputing this incessantly)

Note that zero-length segments are not permitted.

See qe2.core.test.assembler for unit tests.
"""

from qe2.core.log import QE2LOG

FIRST_OFF_IND = 0
LAST_OFF_IND = 1
DATA_IND = 2

class Qe2Assembler(object):

    def __init__(self, base=0):

        # The list of segments.  This is always sorted by
        # first_offset.
        #
        self.segments = list()

        # Base is the current base of the assembly.  When bytes
        # are dequeued from the assembly process, base increases
        # by the corresponding amount.  Any new arrives with a
        # starting offset of less than base are ignored.
        #
        self.base = base

    def add_segment(self, first_offset, segment_data):
        """
        Add new data to the assembler, at the given offset.

        If the new data length is zero, or is entirely in
        the "past" (the last offset is less than self.base)
        then it is ignored.

        The new data is trimmed to remove any data that has
        a first_offset of less than self.base.

        If the data begins before the first segment, then
        use it to fill in the gap between self.base and the
        first segment, then use the new data to fill in any
        holes between other segments, and finally, if there
        is any data with an offset following the end of the
        last segment, add it there.

        Then the set of segments is coalesced as much as
        possible to combine adjacent segments.
        """

        segment_len = len(segment_data)
        last_offset = first_offset + segment_len - 1

        # Empty segments are ignored and are not
        # added to the list of segments.
        #
        if segment_len == 0:
            return

        # Segments entirely from the past are also ignored
        #
        if last_offset < self.base:
            return

        # If the segment begins prior to self.base, trim it so that
        # begins at self.base.
        #
        if first_offset < self.base:
            segment_data = segment_data[self.base - first_offset:]
            segment_len = len(segment_data)
            first_offset = self.base
            last_offset = first_offset + segment_len - 1

        new_seg = [first_offset, last_offset, segment_data]

        # If there aren't any segments, then the new segment
        # becomes the entire list
        #
        if not self.segments:
            self.segments.append(new_seg)
            return

        new_segs = list()

        # If there is a gap between the first segment and self.base,
        # treat it like a hole and try to fill it.
        #
        if self.segments[0][FIRST_OFF_IND] > self.base:
            hole_start = self.base
            hole_last = self.segments[0][FIRST_OFF_IND] - 1

            cover = self.segment_covers(new_seg, hole_start, hole_last)
            if cover:
                # print 'prefix hole [%d %d] cover %s' % (
                #          hole_start, hole_last, str(cover))
                new_segs.append(cover)

        # Find each hole (if any) that the new segment might help
        # fill, and put as much of it as possible into that hole,
        # modify the new segment accordingly, and continue.
        #
        for ind in xrange(len(self.segments) - 1):

            # The hole begins after the end of the current segment
            # and ends before the start of the next.
            #
            hole_start = self.segments[ind][LAST_OFF_IND] + 1
            hole_last = self.segments[ind + 1][FIRST_OFF_IND] - 1

            # print 'check HOLE [%d, %d]' % (hole_start, hole_last)

            cover = self.segment_covers(new_seg, hole_start, hole_last)
            if cover:
                # print 'hole [%d %d] cover %s' % (
                #         hole_start, hole_last, str(cover))
                new_segs.append(cover)
            else:
                # print 'no cover'
                pass

        # Append any remaining part of the new segment.
        #
        final_segs_off = self.segments[-1][LAST_OFF_IND] + 1

        if final_segs_off <= first_offset:
            # print 'case A'
            new_seg = [first_offset, last_offset, segment_data]
            # print new_seg
            new_segs.append(new_seg)

        elif final_segs_off <= last_offset:
            segment_data = segment_data[-(1 + last_offset - final_segs_off):]
            segment_len = len(segment_data)
            first_offset = final_segs_off
            last_offset = first_offset + segment_len - 1

            new_seg = [first_offset, last_offset, segment_data]
            # print 'case B %s' % str(new_seg)

            new_segs.append(new_seg)

        self.segments += new_segs

        # print 'prenorm: %s' % str(self.segments)

        self.normalize_segments()

    def data_ready(self):
        """
        Return the number of bytes that are ready to dequeue, or
        0 if there are none.

        In order for data to be ready, there must be at least one
        segment pending, and it must start at self.base
        """

        segments = self.segments

        if (len(segments) == 0) or (segments[0][FIRST_OFF_IND] != self.base):
            return 0
        else:
            seg = segments[0]

            return 1 + seg[LAST_OFF_IND] - seg[FIRST_OFF_IND]

    def dequeue(self, wanted_len=-1):
        """
        Read as much as wanted_len from the beginning of
        the assembled data, starting at self.base, and increment
        self.base by as much data as read.

        If data_ready() is 0, or wanted_len is zero,
        then return None.

        If wanted_len is -1, then return the data from the entire
        first segment.

        If wanted_len is greater than zero, then return wanted_len
        bytes from the first segment or the entire first segment,
        whichever is shorter.
        """

        segments = self.segments

        if (self.data_ready() == 0) or (wanted_len == 0):
            return None
        elif ((wanted_len == -1) or
                (wanted_len >= len(segments[0][DATA_IND]))):
            self.base = segments[0][LAST_OFF_IND] + 1
            data = segments[0][DATA_IND]
            self.segments = segments[1:]
            return data
        else:
            self.base += wanted_len
            data = segments[0][DATA_IND][:wanted_len]
            self.segments[0][DATA_IND] = segments[0][DATA_IND][wanted_len:]
            self.segments[0][FIRST_OFF_IND] += len(data)
            return data

    @staticmethod
    def segment_covers(segment, hole_start, hole_last):
        """
        Return a segment representing the subset of the hole that
        is covered by the segment, or None of if the segment does
        not overlap the hole
        """

        hole_len = 1 + hole_last - hole_start

        seg_start = segment[FIRST_OFF_IND]
        seg_last = segment[LAST_OFF_IND]
        seg_data = segment[DATA_IND]

        # Need to be very careful with the extents here
        #
        # First check whether the hole overlaps the segment
        # at all, and if not, return None.
        #
        # Then check whether the segment first within the hole.
        #
        # Finally check each of the edge cases
        #
        if (seg_last < hole_start) or (seg_start > hole_last):
            # print 'case X'
            return None

        elif (seg_start <= hole_start) and (seg_last > hole_last):
            start = hole_start - seg_start
            last = start + hole_len
            new_seg = [hole_start, hole_last, seg_data[start:last]]
            # print 'case 0 hole [%d, %d] %s' % (
            #         hole_start, hole_last, str(new_seg))
            return new_seg

        elif (seg_start >= hole_start) and (seg_last <= hole_last):
            return segment

        elif seg_start >= hole_start:
            return [seg_start, hole_last,
                    seg_data[:1 + hole_last - seg_start]]

        elif seg_last >= hole_start:
            return [hole_start, seg_last,
                    seg_data[hole_start - seg_start:]]

        else:
            QE2LOG.error('unhandled case')
            assert(False)

    def normalize_segments(self):
        """
        Coalesce adjacent segments
        """

        # print 'input ' + str(self.segments)

        # Make sure the segments are in offset order
        #
        new_segs = sorted(self.segments, key=lambda seg: seg[FIRST_OFF_IND])

        # Make sure that the segments don't overlap
        # (this is just a sanity check)
        for ind in xrange(len(new_segs) - 1):
            if new_segs[ind][LAST_OFF_IND] > new_segs[ind + 1][FIRST_OFF_IND]:
                QE2LOG.warn('WHOOPS: overlapping segments at %d [%s] and [%s]',
                        ind, str(new_segs[ind]), str(new_segs[ind + 1]))

        # Coalesce: scan through the list of segments from start to end.
        # If two segments are adjacent, set the second segment to be the
        # concatenation of the two segments, and set the first to be None.
        #
        for ind in xrange(len(new_segs) - 1):
            if (new_segs[ind][LAST_OFF_IND] ==
                    (new_segs[ind + 1][FIRST_OFF_IND] - 1)):
                new_segs[ind + 1] = [
                        new_segs[ind][FIRST_OFF_IND],
                        new_segs[ind + 1][LAST_OFF_IND],
                        new_segs[ind][DATA_IND] + new_segs[ind + 1][DATA_IND]]
                new_segs[ind] = None

        # Remove any segments that have been absorbed.
        #
        new_segs = [new_seg for new_seg in new_segs if new_seg]

        self.segments = new_segs

    def first_missing(self):
        """
        Return the starting offset and length of the first "hole" in
        the pending_in assembler, or, if there is no hole, return the
        next offset we are waiting for as the starting offset, and -1
        as its length.

        The first hole might be between self.base and the first segment,
        or between the first and second segments (if there are more than
        one)
        """

        segments = self.segments

        if not segments:
            return (self.base, -1)

        # There's at least one segment: is there a hole between self.base
        # and the start of the first segment?
        #
        elif segments[0][FIRST_OFF_IND] > self.base:
            return (self.base, segments[0][FIRST_OFF_IND] - self.base)
        elif len(segments) == 1:
            return (segments[0][LAST_OFF_IND] + 1, -1)
        else:
            start_hole = segments[0][LAST_OFF_IND] + 1
            end_hole = segments[1][FIRST_OFF_IND] - 1
            len_hole = 1 + end_hole - start_hole

            return (start_hole, len_hole)

    def find_holes(self):
        """
        Return a list of the "holes", if any, in (start, end) notation.
        Return None if there are none.

        The first hole is anything between self.base and the start
        of the first segment.  The rest of the holes are the gaps
        in between the segments.

        The end of the last segment is treated specially: it is
        treated as the beginning of a hole that ends at -1.
        If there are no segments at all, then return [(self.base, -1)]
        """

        holes = list()

        if len(self.segments) == 0:
            holes.append((self.base, -1))
            return holes

        if self.base < self.segments[0][FIRST_OFF_IND]:
            holes.append((self.base, self.segments[0][FIRST_OFF_IND] - 1))

        for i in xrange(len(self.segments) - 1):
            holes.append((self.segments[i][LAST_OFF_IND] + 1,
                    self.segments[i + 1][FIRST_OFF_IND] - 1))

        holes.append((self.segments[-1][LAST_OFF_IND] + 1, -1))

        return holes

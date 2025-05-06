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
Simple queue class for the queues that are used by the Mole encoder
(or anything else that needs a simple queue with some additional state).

NOTE: THIS IS A COPY OF cb.mole.queue from the BBN Curveball package.
Having a copy here means that you can use this module without installing
everything in that package (and all its many dependencies).  We haven't
packaged quilting as its own package yet, but this facilitates doing
that later.
"""

class ByteQueue(object):
    """
    Basic input queue for the mole encoder.

    TODO: what to do if it wraps?
    """

    def __init__(self, base=0, offset=0, content=''):

        if type(base) != int:
            raise TypeError('base must be int (was %s)' % str(type(base)))

        if type(offset) != int:
            raise TypeError('offset must be int (was %s)' % str(type(offset)))

        if type(content) != str:
            raise TypeError('content must be str (was %s)' %
                    str(type(content)))

        self.content = content
        self.base = base
        self.offset = offset
        self.last = self.base + self.offset + len(content)

    def clone(self):
        """
        Create a clone of this ByteQueue
        """

        return ByteQueue(self.get_base(), offset=self.offset,
                content=self.get_content())

    def enq(self, new_content):
        """
        Enqueue new_content to the end of the queue.

        If new_content is non-true, then returns without effect.
        """

        if not new_content:
            return

        #if type(new_content) != str:
        #    raise TypeError('new_content must be str (was %s)' %
        #            str(type(new_content)))

        self.content += new_content
        self.last = self.base + self.offset + len(self.content)

    def deq(self, num):
        """
        Dequeue num bytes from the queue, if there are at least that many bytes
        in the queue.  If there are fewer, dequeue as many as possible.

        It is the responsibility of the caller to check whether the number
        of bytes returned matches the number requested.
        """

        if num < 0:
            raise ValueError('num must be >= 0')
        elif num == 0:
            return ''

        curr_len = self.get_len()
        if num > curr_len:
            num = curr_len

        # Note: using slice notation and len() presumes list representation
        # is used for the underlying content, so these need to be implemented
        # for subclasses that change the representation.
        #
        prefix = self.content[:num]
        self.content = self.content[num:]
        self.offset += len(prefix)
        return prefix

    def deq2(self, num):
        """
        Like deq(), but returns a tuple (data, offset) where data is the
        data returned by calling deque with the given num (which may be
        '' if there is no data to dequeue), and offset is the offset into
        the stream of the first byte of the data.

        A convenience function that can be used, along with a lock around
        the queue itself, to simplify avoiding TOCTTOU errors if there are
        multiple threads accessing the queue.
        """

        offset = self.get_offset()
        data = self.deq(num)

        return (data, offset)

    def peek(self, starting, ending):
        """
        Return a copy of the contents between the given starting and ending
        offsets, inclusive.  The state of the queue is unaltered.

        If the queue does not contain the starting offset, then an IndexError
        is raised.  If the ending offset is smaller than the starting offset,
        then a ValueError is raised.

        If the queue does not contain the ending offset, then a copy of all of
        the data from starting offset to the end is returned.
        """

        if type(starting) != int:
            raise TypeError('starting must be int (not %s)' %
                    str(type(starting)))

        if type(ending) != int:
            raise TypeError('ending must be int (not %s)' %
                    str(type(ending)))

        if (starting < (self.base + self.offset)) or (starting > self.last):
            raise IndexError('starting offset %d outside (%d, %d)' %
                    (starting, self.offset, self.last))

        if starting > ending:
            raise ValueError('starting offset %d > ending offset %d' %
                    (starting, ending))

        # Note: assumes that slice notation works on the representation
        # of content.
        #
        beg = starting - (self.base + self.offset)
        end = ending - (self.base + self.offset)
        return self.content[beg:end]

    def discard(self, num):
        """
        Dequeue num bytes from the queue, if there are at least that many bytes
        in the queue.  If there are fewer, dequeue as many as possible.

        The dequeued bytes are discarded.
        """

        self.deq(num)

    def set_base(self, new_base):
        """
        Reset the base to a new value.

        May be useful if this queue is tracking positions in some other
        data structure (for example, TCP sequence numbers) that may wrap
        or be reset.
        """

        if type(new_base) != int:
            raise TypeError('new_base must be int (was %s)' %
                    str(type(new_base)))

        self.base = new_base

    def set_offset(self, new_offset):
        """
        Reset the offset to a new value.

        May be useful if this queue is tracking positions in some other
        data structure (for example, TCP sequence numbers) that may wrap
        or be reset.
        """

        if type(new_offset) != int:
            raise TypeError('new_offset must be int (was %s)' %
                    str(type(new_offset)))

        self.offset = new_offset
        self.last = self.offset + len(self.content)

    def get_len(self):
        """
        Return the number of bytes present in the queue
        """

        return self.last - (self.base + self.offset)

    def get_base(self):
        """
        Return the base of the queue (the initial offset)
        """

        return self.base

    def get_offset(self):
        """
        Return the offset of the current head of the queue
        """

        return self.offset

    def get_last(self):
        """
        Return the offset of the current tail of the queue
        """

        return self.last

    def get_content(self):
        """
        Return a pointer to a string representing the current content of
        the queue (starting at the head)
        """

        return self.content


class FastByteQueue(ByteQueue):
    """
    Specialized subclass of ByteQueue, intended to make operations
    faster for queues that grow long (perhaps multiple megabytes)
    by ensuring that all of the operations take place on short
    subspans of the queue

    The queue is divided into spans, where each span is exactly
    MAX_SPAN_LEN in length, with the possible exception of the
    first and last spans (which may be less than full).
    """

    # TODO: experiment with the SPAN size to find the best fit.
    # It needs to be at, smallest, something larger than the MTU size
    # (to make the math easy, say 4 times the MTU, which is typically
    # 1500).  Making it larger reduces the amortized cost of some
    # operations while increasing others; it gets expensive above
    # 128K.  Choosing something in the middle for now.
    #
    MAX_SPAN_LEN = 10 * 1024

    def __init__(self, base=0, offset=0, content=''):
        super(FastByteQueue, self).__init__(base, offset, content)

        self.spans = list()
        self.enq(content)

    def enq(self, new_content):
        """
        Enqueue new_content to the end of the queue.

        If new_content is non-true, then returns without effect.
        """

        if not new_content:
            return

        n_spans = len(self.spans)
        if n_spans == 0:
            self.spans.append('')

        buf = new_content

        # If there's any more space in the last span, put
        # as of the buf as will fit into that span.
        #
        to_fill = self.MAX_SPAN_LEN - len(self.spans[-1])
        self.spans[-1] += buf[:to_fill]
        buf = buf[to_fill:]

        # If there's anything left in the buf after filling in
        # the last span, then chop buf up into MAX_SPAN_LEN-length
        # chunks and append the chunks. (the last chunk might not
        # be MAX_SPAN_LEN, of course)
        #
        if len(buf):
            for offset in xrange(0, 1 + (len(buf) / self.MAX_SPAN_LEN)):
                start = offset * self.MAX_SPAN_LEN
                end = start + self.MAX_SPAN_LEN

                self.spans.append(buf[start:end])

        self.last += len(new_content)

    def deq(self, num):
        if num < 0:
            raise ValueError('num must be >= 0')
        elif num == 0:
            return ''

        curr_len = self.get_len()
        if num > curr_len:
            num = curr_len

        deq_buf = ''
        while (len(self.spans) > 0) and (len(self.spans[0]) <= num):
            num -= len(self.spans[0])
            deq_buf += self.spans[0]
            self.spans = self.spans[1:]

        if (len(self.spans) > 0) and num:
            deq_buf += self.spans[0][:num]
            self.spans[0] = self.spans[0][num:]

        self.offset += len(deq_buf)
        return deq_buf

    def peek(self, starting, ending):
        """
        WARNING: assumes that the things peeked are generally small,
        fitting in two adjacent spans.
        """

        if (starting < (self.base + self.offset)) or (starting > self.last):
            raise IndexError('starting offset %d outside (%d, %d)' %
                    (starting, self.offset, self.last))

        if starting > ending:
            raise ValueError('starting offset %d > ending offset %d' %
                    (starting, ending))

        if len(self.spans) == 0:
            return ''

        beg = starting - (self.base + self.offset)
        end = ending - (self.base + self.offset)
        peek_len = end - beg

        # the fact that the first span might not be full makes
        # the offset calculation more complicated
        #
        first_len = len(self.spans[0])
        if beg < first_len:
            beg_span = 0
            chunk = self.spans[beg_span][beg:beg + peek_len]
        else:
            base = beg + (self.MAX_SPAN_LEN - first_len)
            beg_span = base / self.MAX_SPAN_LEN

            l_off = base % self.MAX_SPAN_LEN
            chunk = self.spans[beg_span][l_off:l_off + peek_len]

        if len(chunk) < peek_len:
            chunk += self.spans[beg_span + 1][:peek_len - len(chunk)]

        return chunk

    def get_content(self):
        """
        Return a pointer to a string representing the current content of
        the queue (starting at the head)
        """

        return ''.join(self.spans)

    def discard(self, num):
        """
        Dequeue num bytes from the queue, if there are at least that many bytes
        in the queue.  If there are fewer, dequeue as many as possible.

        The dequeued bytes are discarded.
        """

        num_discarded = 0

        while self.spans and (num >= len(self.spans[0])):
            num_discarded += len(self.spans[0])
            num -= len(self.spans[0])
            self.spans = self.spans[1:]

        if self.spans and num:
            if num > len(self.spans[0]):
                num_discarded += len(self.spans[0])
            else:
                num_discarded += num

            self.spans[0] = self.spans[0][num:]

        self.offset += num_discarded


if __name__ == '__main__':
    import sys

    def test_fast_basic():
        """
        Test basic functionality
        """

        print 'test_fast_basic'

        queue1 = FastByteQueue(content='abcd')
        assert(queue1.deq(1) == 'a')
        assert(queue1.deq(1) == 'b')
        assert(queue1.deq(1) == 'c')
        assert(queue1.deq(1) == 'd')
        assert(queue1.deq(1) == '')

        queue1 = FastByteQueue(content='abcd')
        assert(queue1.deq(4) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = FastByteQueue(content='abcd')
        assert(queue1.deq(6) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = FastByteQueue()
        queue1.enq('abcd')
        queue1.enq('efghi')
        queue1.enq('xxxxx')
        assert(queue1.deq(2) == 'ab')
        assert(queue1.deq(2) == 'cd')
        assert(queue1.deq(2) == 'ef')
        assert(queue1.deq(2) == 'gh')
        assert(queue1.deq(2) == 'ix')
        assert(queue1.deq(2) == 'xx')

        queue1 = FastByteQueue()
        queue1.enq('a')
        queue1.enq('b')
        queue1.enq('c')
        queue1.enq('d')
        queue1.enq('e')
        queue1.enq('f')
        queue1.enq('g')
        assert(queue1.deq(4) == 'abcd')
        assert(queue1.deq(4) == 'efg')

        queue1 = FastByteQueue()
        queue1.enq('a')
        queue1.enq('b')
        assert(queue1.deq(4) == 'ab')
        assert(queue1.deq(1) == '')

        queue1.enq('c')
        queue1.enq('d')
        assert(queue1.deq(4) == 'cd')
        assert(queue1.deq(1) == '')

        queue1 = FastByteQueue()
        queue1.enq('abc')
        assert(queue1.deq(2) == 'ab')
        queue1.enq('def')
        assert(queue1.deq(2) == 'cd')
        assert(queue1.deq(2) == 'ef')
        assert(queue1.deq(2) == '')

        return 0

    def test_fast_peek():
        """
        Test whether fast peeks work properly
        """

        print 'test_fast_peek'

        queue1 = FastByteQueue(base=10, content='abcdefgh')
        assert(queue1.deq(1) == 'a')
        assert(queue1.peek(12, 14) == 'cd')
        queue1.enq('ijk')
        assert(queue1.peek(12, 13) == 'c')
        assert(queue1.peek(13, 14) == 'd')
        assert(queue1.peek(14, 15) == 'e')
        assert(queue1.peek(15, 16) == 'f')
        assert(queue1.peek(16, 17) == 'g')
        assert(queue1.peek(17, 18) == 'h')

        assert(queue1.peek(12, 14) == 'cd')
        assert(queue1.peek(13, 15) == 'de')
        assert(queue1.peek(14, 16) == 'ef')
        assert(queue1.peek(15, 17) == 'fg')
        assert(queue1.peek(16, 18) == 'gh')

        assert(queue1.peek(12, 15) == 'cde')
        assert(queue1.peek(13, 16) == 'def')
        assert(queue1.peek(14, 17) == 'efg')
        assert(queue1.peek(15, 18) == 'fgh')

        try:
            print queue1.peek(10, 11)
        except IndexError:
            pass
        except:
            assert False

        try:
            print queue1.peek(21, 22)
        except IndexError:
            pass
        except:
            assert False

        return 0

    def test_fast_discard():
        """
        Test whether discards work properly
        """

        print 'test_fast_discard'

        queue1 = FastByteQueue(base=10, content='abcdefghijklmnopqrstuvwxyz')

        assert(queue1.peek(21, 24) == 'lmn')
        assert(queue1.get_offset() == 0)
        queue1.discard(1)
        assert(queue1.get_offset() == 1)
        assert(queue1.peek(21, 24) == 'lmn')
        queue1.discard(1)
        assert(queue1.get_offset() == 2)
        assert(queue1.peek(21, 24) == 'lmn')
        queue1.discard(3)
        assert(queue1.get_offset() == 5)
        assert(queue1.peek(21, 24) == 'lmn')
        queue1.discard(5)
        assert(queue1.get_offset() == 10)
        assert(queue1.peek(21, 24) == 'lmn')

    def test_basic():
        """
        Test basic functionality
        """

        print 'test_basic'

        queue1 = ByteQueue(content='abcd')
        assert(queue1.deq(1) == 'a')
        assert(queue1.deq(1) == 'b')
        assert(queue1.deq(1) == 'c')
        assert(queue1.deq(1) == 'd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue(content='abcd')
        assert(queue1.deq(4) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue(content='abcd')
        assert(queue1.deq(6) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue()
        queue1.enq('abcd')
        assert(queue1.deq(4) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue()
        queue1.enq('a')
        queue1.enq('b')
        queue1.enq('c')
        queue1.enq('d')
        assert(queue1.deq(4) == 'abcd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue()
        queue1.enq('a')
        queue1.enq('b')
        assert(queue1.deq(4) == 'ab')
        assert(queue1.deq(1) == '')

        queue1.enq('c')
        queue1.enq('d')
        assert(queue1.deq(4) == 'cd')
        assert(queue1.deq(1) == '')

        queue1 = ByteQueue()
        queue1.enq('abc')
        assert(queue1.deq(2) == 'ab')
        queue1.enq('def')
        assert(queue1.deq(2) == 'cd')
        assert(queue1.deq(2) == 'ef')
        assert(queue1.deq(2) == '')

        return 0

    def test_peek():
        """
        Test whether peeks work properly
        """

        print 'test_peek'

        queue1 = ByteQueue(base=10, content='abcd')
        assert(queue1.deq(2) == 'ab')
        assert(queue1.peek(12, 14) == 'cd')
        queue1.enq('efg')
        assert(queue1.peek(12, 16) == 'cdef')
        assert(queue1.peek(12, 13) == 'c')

        return 0

    def test_discard():
        """
        Test whether discards work properly
        """

        print 'test_discard'

        queue1 = ByteQueue(base=10, content='abcdefghijklmnopqrstuvwxyz')

        assert(queue1.peek(21, 24) == 'lmn')
        print queue1.get_offset()
        queue1.discard(1)
        print queue1.get_offset()
        assert(queue1.peek(21, 24) == 'lmn')
        queue1.discard(1)
        print queue1.get_offset()
        assert(queue1.peek(21, 24) == 'lmn')
        queue1.discard(3)
        print queue1.get_offset()
        assert(queue1.peek(21, 24) == 'lmn')
        print queue1.get_content()
        print queue1

    def test_deq2():
        """
        Test of deq2()
        """

        queue1 = ByteQueue(offset=10, content='abcdefghijklmnopqrstuvwxyz')

        try:
            test = 1
            assert(queue1.deq2(0) == ('', 10))
            test = 2
            assert(queue1.deq2(2) == ('ab', 10))
            test = 3
            assert(queue1.deq2(2) == ('cd', 12))
            test = 4
            assert(queue1.deq2(0) == ('', 14))
            test = 5
            assert(queue1.deq2(5) == ('efghi', 14))
            test = 6
            assert(queue1.deq2(20) == ('jklmnopqrstuvwxyz', 19))
            test = 7
            assert(queue1.deq2(20) == ('', 36))
        except BaseException, _exc:
            print 'FAILED: deq2 test %d' % test
            return 1

        return 0

    def test_main():
        """
        Tester for ByteQueue
        """

        status = 0

        if test_basic():
            print 'test_basic FAILED'
            status = 1

        if test_peek():
            print 'test_basic FAILED'
            status = 1

        if test_discard():
            print 'test_discard FAILED'
            status = 1

        # To make small tests meaningful, make
        # the span size tiny.

        FastByteQueue.MAX_SPAN_LEN = 3

        if test_fast_basic():
            print 'test_fast_basic FAILED'

        if test_fast_peek():
            print 'test_fast_peek FAILED'

        if test_fast_discard():
            print 'test_fast_discard FAILED'

        if test_deq2():
            print 'test_deq2 FAILED'

        if status:
            print 'FAILED'
        else:
            print 'SUCCESS'

        return status

    sys.exit(test_main())

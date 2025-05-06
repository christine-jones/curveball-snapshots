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
The DP side of the mole protocol.

See mole.txt for a more detailed description.
"""

from cb.mole.queue import FastByteQueue

class MoleTunnelDp(object):
    """
    See mole.txt.

    This mole tunnel is specialized for TCP.  This is not a
    disaster, because all near-term moles are likely to be TCP
    or IPsec, and IPsec uses a sequencing mechanism that is
    functionally similar to TCP, so we might be able to reuse
    it almost as-is.
    """

    def __init__(self, encoder, base_seq=0, content=''):
        """
        encoder - an instance of a MoleEncoder

        base_seq - the sequence number of the first TCP packet that
        we are using.  This is not the sequence number on the initial
        SYN packet -- this is the sequence number of the first packet
        that the mole tunnel fills with new data.  This packet is
        assumed to arrive in order: no packets with earlier sequence
        numbers should arrive after this.  If they do, the mole will fail.
        The connection monitor should check that this is the expected packet.
        """

        self.encoder = encoder
        self.base_seq = base_seq
        self.ccp_unencoded = FastByteQueue(content=content)
        self.encoded_pending = FastByteQueue(base=base_seq)

    def get_session_key(self):
        return self.encoder.get_session_key()

    def enqueue(self, content):
        """
        Add new content (usually from the Covert->Client CCP stream) to the
        ccp_unencoded queue.

        No return value.
        """

        self.ccp_unencoded.enq(content)

    def extend(self, last_seq):
        """
        Extend the encoding until the length of the encoding_pending
        covers at least the given sequence number.

        Extends the encoding as far as possible with data from ccp_unencoded.
        When ccp_unencoded is exhausted, fills the rest with chaff.
        """

        #print "ooooooooooooooooooooooooooooooooooooooooo"
        #print self.ccp_unencoded.get_content()
        #print "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

        #print "unencoded queue %d" % len(self.ccp_unencoded.get_content())

        # Maybe we've already extended far enough?
        #
        if self.encoded_pending.get_last() >= last_seq:
            return

        chunk_len = self.encoder.MAX_UNENCODED_CHUNK_LEN

        # See if there's anything waiting in ccp_unencoded.  If there
        # is, then start encoding it until we've reached last_seq
        # or we run out of ccp_unencoded.
        #
        while ((self.ccp_unencoded.get_len() > 0) and
                (self.encoded_pending.get_last() < last_seq)):

            ccp_offset = self.ccp_unencoded.get_offset()
            unencoded_chunk = self.ccp_unencoded.deq(chunk_len)
            encoded_chunk = self.encode_data(
                    unencoded_chunk, ccp_offset, chaff_length=0)

            self.encoded_pending.enq(encoded_chunk)

        ccp_offset = self.ccp_unencoded.get_offset()

        # If we escaped the previous loop because we reached the
        # desired offset, then we're finished.  Otherwise, keep
        # adding chaff until we extend encoded_pending far enough.

        while self.encoded_pending.get_last() < last_seq:

            # TODO: BOGUS! this is a bad heuristic.  We should add as little
            # chaff as necessary, not as much as possible.
            encoded_chunk = self.encode_data('', 0,
                    chaff_length=self.encoder.MAX_UNENCODED_CHUNK_LEN)

            self.encoded_pending.enq(encoded_chunk)
        
    def encode_data(self, data, ccp_offset, chaff_length=0):
        """
        Encode the unencoded data (chaff, or data from ccp_unencoded)
        in the final form it will take in encoded_pending.

        This form depends on the nature of the tunnel: for HTTP,
        it's just the generic mole encoding.  For other tunnels,
        however, there may be additional steps.
        """

        return self.encoder.encode(data, ccp_offset, chaff_length)

    def copy(self, start_seq, length):
        """
        Return a copy of the contents of encoded_pending, starting at the
        start_seq and continuing for the given length.  If either of
        start_seq or (start_seq + length) is outside of the extent of
        encoded_pending, then None is returned.

        For debugging purposes, this prints messages to stdout if used
        incorrectly.  FIXME: this is lame.
        """

        if length <= 0:
            print 'MoleTunnelDp.copy: length < 0'
            return None

        if start_seq < self.base_seq:
            print 'MoleTunnelDp.copy: start_seq < self.base_seq'
            return None

        last_seq = start_seq + length

        if last_seq > self.encoded_pending.get_last():
            print 'MoleTunnelDp.copy: last_seq too large'
            return None

        return self.encoded_pending.peek(start_seq, last_seq)

    def reset_base(self, new_start_seq):
        """
        Discard the contents of encoded_pending, up to the given
        new_start_seq.  The new_start_seq must be less than or equal
        to the last offset in the encoded_pending, and greater than or
        equal to the first offset.  If the new_start_seq is outside
        this range, this call has no effect (no even an exception)
        except for griping.
        """

        base = self.encoded_pending.get_base()
        head_seq = base + self.encoded_pending.get_offset()
        tail_seq = base + self.encoded_pending.get_last()

        # print "DISCARD new %.8d base %.8d head %.8d tail %.8d" % (
        #         new_start_seq, base, head_seq, tail_seq)

        if new_start_seq < head_seq:
            print "ERROR: DISCARD new < head"
            return

        if new_start_seq > tail_seq:
            print "ERROR: DISCARD new > tail"
            return

        discard_len = new_start_seq - head_seq
        # print 'DISCARD len %d' % discard_len

        self.encoded_pending.discard(discard_len)


class TLSMoleTunnelDp(MoleTunnelDp):
    """
    Extension of the MoleTunnelDp to handle create TLS
    records in the encoded queue, instead of the plaintext
    used by the HTTP mole.
    """

    def __init__(self, encoder, cssl, base_seq=0, content=''):
        super(TLSMoleTunnelDp, self).__init__(encoder, base_seq, content)

        self.cssl = cssl

    def encode_data(self, data, ccp_offset, chaff_length=0):
        """
        Encode the data using the mole encoder, and then turn it
        into TLS records.
        """

        raw_data = super(TLSMoleTunnelDp, self).encode_data(data,
                ccp_offset, chaff_length)

        ssl_data = self.cssl.create_data_record(raw_data)

        return ssl_data


if __name__ == '__main__':
    from cb.mole.debug import TestMoleEncoder
    from cb.mole.encode import HttpMoleEncoder
    from cb.mole.c_encode import HttpMoleCryptoEncoder

    def test_main():

        text1 = 'Mary had a little lamb, a little pork, a little ham\n'
        text2 = 'And when they carried Mary out, her face was white as snow'
        results = dict()

        # Check that the initial sequence number has no effect on
        # the encoded data.
        #
        for seqno in [0, 1000, 2000, 10000]:
            encoder = HttpMoleCryptoEncoder('foo.com', 'foo.com')
            # Just for debugging
            # encoder.MAX_UNENCODED_CHUNK_LEN = 64
            tunnel = MoleTunnelDp(encoder, seqno)

            for ext in [0, 300]:
                tunnel.extend(seqno + ext)
                assert tunnel.encoded_pending.get_content() > ext

            tunnel.enqueue(text1)

            for ext in [600, 900]:
                tunnel.extend(seqno + ext)
                assert tunnel.encoded_pending.get_content() > ext

            tunnel.enqueue(text2)

            for ext in [1200, 1300]:
                tunnel.extend(seqno + ext)
                assert tunnel.encoded_pending.get_content() > ext

            results[seqno] = tunnel.encoded_pending.get_content()

            if seqno > 0:
                assert results[seqno] == results[0]

            offset = seqno
            tot_chunk = ''
            while True:
                chunk = tunnel.copy(offset, 100)
                if chunk == None:
                    break
                offset += len(chunk)
                tot_chunk += chunk
                print len(tot_chunk)

            assert tot_chunk == results[seqno][:len(tot_chunk)]
            print len(tot_chunk)


        #print results[0]

        # Check that the data decodes properly
        #
        decoder = HttpMoleCryptoEncoder('foo.com', 'foo.com')
        urls = [url.strip() for url in results[0].split('GET') if url]
        res_text = ''
        for url in urls:
            print url
            (offset, text) = decoder.decode_response(url)
            res_text += text

        assert res_text == (text1 + text2)

        #print res_text

    exit(test_main())

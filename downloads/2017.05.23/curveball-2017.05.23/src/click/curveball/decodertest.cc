/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 *
 * Copyright 2014 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <click/config.h>
#include "decodertest.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS


DecoderTest::DecoderTest()
    : _pktbuf(NULL), _header_needed(false), _bytes_remaining(0)
{
}

DecoderTest::~DecoderTest()
{
    release_pkt_buffer();
}

void
DecoderTest::push(int, Packet *p)
{
    parse(p);
}

void
DecoderTest::parse(Packet *p)
{
    bool done = false;
    while (!done) {
        // Handle partial DR2DP message.
        if (_pktbuf != NULL) {
            p = append_to_pkt_buffer(p);
            if (p == NULL) {
                return;
            }
        }

        const dr2dp_msg *msg = reinterpret_cast<const dr2dp_msg *>(p->data());

        if (p->length() < sizeof(dr2dp_msg)) {
            // Entire DR2DP message header not present;
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(p);
            return;
        }

        if (msg->protocol != DR2DP_PROTOCOL_VERSION) {
            click_chatter("DecoderTest::parse: "
                          "Invalid DR2DP protocol version %d", msg->protocol);
            p->kill();
            return;
        }

        Packet *pkt = p;
        bool release_pkt = true;
        uint64_t pkt_length = sizeof(dr2dp_msg) + ntohq(msg->data_length);

        if (pkt->length() < pkt_length) {
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(pkt, pkt_length);
            return;

        } else if (pkt->length() > pkt_length) {
            // DR2DP message accounts for only part of the packet buffer.
            pkt = p->clone();
            pkt->take(pkt->length() - pkt_length);
            p->pull(pkt_length);

        } else { // pkt->length() == pkt_length
            done = true;
        }

        // Process a fully recieved DR2DP message.
        switch (msg->operation_type) {

        // Packet to be forwarded on behalf of decoy proxy.
        case DR2DP_OP_TYPE_FORWARD:
            click_chatter("DecoderTest::parse: forward message received");

            // push packet out the element's outbound interface
            output(0).push(pkt);
            release_pkt = false;

            break;

        case DR2DP_OP_TYPE_REDIRECT_FLOW: {
            click_chatter("DecoderTest::parse: redirect message received");

            const dr2dp_msg *msg_hdr =
                      reinterpret_cast<const dr2dp_msg *>(pkt->data());
            uint64_t data_length = ntohq(msg_hdr->data_length);
            if (data_length < sizeof(dr2dp_redirect_flow_msg)) {
                click_chatter("DecoderTest:parse:: invalid data length");
                break;
            }

            pkt->pull(sizeof(dr2dp_msg));
            const dr2dp_redirect_flow_msg *redirect_msg =
                 reinterpret_cast<const dr2dp_redirect_flow_msg *>(pkt->data());
            int syn_option_length = redirect_msg->syn_option_length;
            int ack_option_length = redirect_msg->ack_option_length;

            pkt->pull(sizeof(dr2dp_redirect_flow_msg));
            pkt->pull(syn_option_length);
            pkt->pull(ack_option_length);

            data_length -= sizeof(dr2dp_redirect_flow_msg);
            data_length -= syn_option_length;
            data_length -= ack_option_length;

            assert(data_length == pkt->length());

            int new_pkt_len = sizeof(dr2dp_msg) + data_length;

            WritablePacket *new_pkt = WritablePacket::make(new_pkt_len);
            if (!new_pkt) {
                click_chatter("DecoderTest::parse: failed to create packet");
                break;
            }

            dr2dp_msg *new_msg = reinterpret_cast<dr2dp_msg *>(new_pkt->data());
            new_msg->protocol = DR2DP_PROTOCOL_VERSION;
            new_msg->session_type = 0;
            new_msg->message_type = DR2DP_MSG_TYPE_REQUEST;
            new_msg->operation_type = DR2DP_OP_TYPE_FORWARD;
            new_msg->response_code = 0;
            new_msg->xid = 0;
            new_msg->data_length = htonq(data_length);

            memcpy(new_pkt->data() + sizeof(dr2dp_msg),
                   pkt->data(), data_length);

            output(0).push(new_pkt);
            break;
        }

        default:
            click_chatter("DecoderTest::parse: "
                          "Unsupported DR2DP operation type %d",
                          msg->operation_type);
            break;
        }

        if (release_pkt) {
            // No longer need the packet data; release memory.
            pkt->kill();
        }
    }

    return;
}

void
DecoderTest::new_pkt_buffer(Packet *p, uint64_t length_needed)
{
    assert(_pktbuf == NULL);
    assert(length_needed == 0 || length_needed > p->length());

    _pktbuf = p;
    _pktbuf->set_prev(NULL);
    _pktbuf->set_next(NULL);

    if (length_needed == 0) {
        _header_needed = true;
        _bytes_remaining = sizeof(dr2dp_msg) - p->length();

    } else {
        _bytes_remaining = length_needed - p->length();
    }
}

Packet *
DecoderTest::append_to_pkt_buffer(Packet *p)
{
    assert(_pktbuf != NULL);
    assert(_bytes_remaining > 0);

    if (_header_needed) {
        if (_bytes_remaining > p->length()) {
            add_pkt(p);
            p = NULL;
            return p;
        }

        dr2dp_msg msg_hdr;
        memset(&msg_hdr, 0, sizeof(dr2dp_msg));

        // Build complete copy of DR2DP message header.
        Packet *pkt = _pktbuf;
        unsigned char *cur_pos = (unsigned char *)&msg_hdr;
        do {
            memcpy(cur_pos, pkt->data(), pkt->length());
            cur_pos += pkt->length();
            pkt = pkt->next();
        } while (pkt != _pktbuf && pkt != NULL);

        assert((cur_pos + _bytes_remaining) ==
               ((unsigned char *)&msg_hdr + sizeof(dr2dp_msg)));

        memcpy(cur_pos, p->data(), _bytes_remaining);

        _bytes_remaining += ntohq(msg_hdr.data_length);
        _header_needed = false;
    }

    if (_bytes_remaining >= p->length()) {
        add_pkt(p);
        p = NULL;

    } else {
        Packet * pkt = p->clone();
        pkt->take(pkt->length() - _bytes_remaining);
        p->pull(_bytes_remaining);

        add_pkt(pkt);
        assert(_bytes_remaining == 0);
    }

    if (_bytes_remaining == 0) {
        process_pkt_buffer();
    }

    return p;
}

void
DecoderTest::add_pkt(Packet *p)
{
    assert(_pktbuf);

    if (_pktbuf->prev() == NULL) {
        assert(_pktbuf->next() == NULL);

        _pktbuf->set_next(p);
        _pktbuf->set_prev(p);
        p->set_next(_pktbuf);
        p->set_prev(_pktbuf);

    } else {
        assert(_pktbuf->prev() != NULL);
        assert(_pktbuf->next() != NULL);

        _pktbuf->prev()->set_next(p);
        p->set_prev(_pktbuf->prev());
        _pktbuf->set_prev(p);
        p->set_next(_pktbuf);
    }

    _bytes_remaining -= p->length();
}

void
DecoderTest::process_pkt_buffer()
{
    assert(_header_needed == false);
    assert(_bytes_remaining == 0);
    assert(_pktbuf->next() != NULL);

    uint64_t orig_len = _pktbuf->length();
    uint64_t curr_len = _pktbuf->length();

    uint64_t data_len_to_add = 0;
    for (Packet *p = _pktbuf->next(); p != _pktbuf; p = p->next()) {
        data_len_to_add += p->length();
    }

    // Remove first packet from buffer.
    Packet * first_pkt = _pktbuf;
    _pktbuf->prev()->set_next(_pktbuf->next());
    _pktbuf->next()->set_prev(_pktbuf->prev());
    _pktbuf = _pktbuf->next();
    first_pkt->set_next(NULL);
    first_pkt->set_prev(NULL);

    // Create new packet to contain the total assembled DR2DP message.
    WritablePacket * pkt = first_pkt->put(data_len_to_add);
    if (pkt == NULL) {
        click_chatter("DecoderTest::process_pkt_buffer: "
                      "failed to allocate packet");
        release_pkt_buffer();
        return;
    }

    // Copy message pieces from remaining packets to new packet buffer.
    Packet *p = _pktbuf;
    unsigned char * end_data = pkt->data() + curr_len;
    do {
        memcpy(end_data, p->data(), p->length());
        end_data += p->length();
        curr_len += p->length();
        p = p->next();
    } while (p != _pktbuf);
    assert(curr_len == orig_len + data_len_to_add);

    release_pkt_buffer();

    // Process complete DR2DP message.
    parse(pkt);
}

void
DecoderTest::release_pkt_buffer()
{
    _header_needed = false;
    _bytes_remaining = 0;

    if (_pktbuf == NULL) {
        return;
    }

    if (_pktbuf->prev() != NULL) {
        _pktbuf->prev()->set_next(NULL);
    }

    Packet * p = _pktbuf;
    Packet * tmp = NULL;

    while (p != NULL) {
        tmp = p;
        p = p->next();
        tmp->kill();
    }

    _pktbuf = NULL;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(DecoderTest)

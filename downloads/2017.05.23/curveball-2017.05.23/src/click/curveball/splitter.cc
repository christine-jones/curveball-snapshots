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
#include "splitter.hh"
#include <click/confparse.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


void
SplitterTable::add_flow(const IPFlowID &flow_key)
{
    // Check that a flow entry does not already exist.
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        click_chatter("SplitterTable::add_flow: flow entry already exists %s",
                      flow_key.unparse().c_str());
        return;
    }

    // Insert entry into flow table.
    _flow_table.set(flow_key, SplitterEntry());
}

void
SplitterTable::remove_flow(const IPFlowID &flow_key)
{
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        _flow_table.erase(flow_key);
    }
}

Splitter::Splitter()
    : _segment_size(10), _segment_all(false),
      _reverse(false), _mix_it_up(false), _flow_table()
{
}

Splitter::~Splitter()
{
}

int
Splitter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "SEGMENT_SIZE", 0, cpUnsigned, &_segment_size,
                        "SEGMENT_ALL", 0, cpBool, &_segment_all,
                        "REVERSE", 0, cpBool, &_reverse,
                        "MIX_IT_UP", 0, cpBool, &_mix_it_up,
                        cpEnd);
}

void
Splitter::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are simply forwarded.
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());
    unsigned int port = ntohs(p->tcp_header()->th_dport);

    if (port == 443) {
        process_packet(p, tls_sentinel_packet(p));

    } else if (port == 80) {
        process_packet(p, http_sentinel_packet(p));

    } else {
        output(0).push(p);
    }
}

void
Splitter::process_packet(Packet *p, bool sentinel_packet)
{
    IPFlowID flow_key = IPFlowID(p);

    if (syn_packet(p)) {
        _flow_table.add_flow(flow_key);
        output(0).push(p);
        return;
    }

    SplitterEntry *entry = _flow_table.get_flow(flow_key);
    if (entry == NULL) {
        output(0).push(p);
        return;
    }

    if (sentinel_packet) {
        entry->set_sentinel_pkt_seen();
        split_packet(p);
        return;
    }

    if (!entry->sentinel_pkt_seen()) {
        output(0).push(p);
        return;
    }

    assert(entry->sentinel_pkt_seen());

    if (_segment_all) {
        split_packet(p);
        return;
    }

    output(0).push(p);
}

bool
Splitter::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

bool
Splitter::tls_sentinel_packet(Packet *p)
{
    assert(ntohs(p->tcp_header()->th_dport) == 443);

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.

    return ((nbytes >= 6) && (data[0] == 0x16 && data[5] == 0x01));
}

bool
Splitter::http_sentinel_packet(Packet *p)
{
    assert(ntohs(p->tcp_header()->th_dport) == 80);

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    String pkt_str((const char *)data, nbytes);
    String start_of_msg_str("GET");

    if (pkt_str.length() < start_of_msg_str.length()) {
        return false;
    }

    return (pkt_str.find_left(start_of_msg_str) == 0);
}

void
Splitter::split_packet(Packet *p)
{
    click_chatter("SPLIT PACKET");

    const uint8_t *orig_data = p->transport_header() +
                               (p->tcp_header()->th_off << 2);
    int orig_bytes = p->end_data() - orig_data;

    Vector<WritablePacket *> _segment_queue;

    int split_bytes = 0;
    while (split_bytes < orig_bytes) {

        int copy_bytes = _segment_size;
        if (orig_bytes - split_bytes < _segment_size) {
            copy_bytes = orig_bytes - split_bytes;
        }

        int removed_bytes = orig_bytes - copy_bytes;
        int new_pkt_len = p->length() - removed_bytes;
        int header_len = p->network_header_length() +
                         (p->tcp_header()->th_off << 2);

        assert(new_pkt_len == header_len + copy_bytes);

        WritablePacket *split_p = WritablePacket::make(new_pkt_len);
        if (split_p == NULL) {
            click_chatter("Failed to allocate split packet.");
            return;
        }

        // copy network headers
        memcpy(split_p->data(), p->data(), header_len);
        split_p->set_network_header(split_p->data(),
                                    p->network_header_length());

        // copy tcp data
        uint8_t *split_data = split_p->transport_header() +
                              (split_p->tcp_header()->th_off << 2);
        memcpy(split_data, orig_data + split_bytes, copy_bytes); 

        // update tcp sequence number
        int orig_seq = ntohl(p->tcp_header()->th_seq);
        split_p->tcp_header()->th_seq = htonl(orig_seq + split_bytes);

        // update ip packet length
        int orig_len = ntohs(p->ip_header()->ip_len);
        split_p->ip_header()->ip_len = htons(orig_len - removed_bytes);

        // ip/tcp header checksums re-calculated by subsequent elements

        split_bytes += copy_bytes;

        if (_mix_it_up && (_segment_queue.size() % 2)) {
            _segment_queue.push_front(split_p);
        } else {
            _segment_queue.push_back(split_p);
        }
    }

    assert(split_bytes == orig_bytes);

    while (!_segment_queue.empty()) {
        WritablePacket *send_p = (WritablePacket *)NULL;
        if (_reverse) {
            send_p = _segment_queue.back();
        } else {
            send_p = _segment_queue.front();
        } 

        output(0).push(send_p);

        if (_reverse) {
            _segment_queue.pop_back();
        } else {
            _segment_queue.pop_front();
        }
    }

    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Splitter)

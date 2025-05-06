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
#include "packetsplitter.hh"
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


PacketSplitter::PacketSplitter()
    : _port(80), _segment_size(10)
{
}

PacketSplitter::~PacketSplitter()
{
}

int
PacketSplitter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "PORT", 0, cpTCPPort, &_port,
                        "SEGMENT_SIZE", 0, cpUnsigned, &_segment_size,
                        cpEnd);
}

void
PacketSplitter::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // simply forward non-first packet fragments
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());

    // simply forward packets not destined to the configured port
    if (ntohs(p->tcp_header()->th_dport) != _port) {
        output(0).push(p);
        return;
    }

    if (syn_packet(p) || ack_packet(p)) {
        output(0).push(p);
    } else {
        split_packet(p);
    }
}

bool
PacketSplitter::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

bool
PacketSplitter::ack_packet(Packet *p)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    return ((p->tcp_header()->th_flags & TH_ACK) && (nbytes == 0));
}

void
PacketSplitter::split_packet(Packet *p)
{
    const uint8_t *orig_data = p->transport_header() +
                               (p->tcp_header()->th_off << 2);
    int orig_bytes = p->end_data() - orig_data;

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

        output(0).push(split_p);
    }

    assert(split_bytes == orig_bytes);

    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(PacketSplitter)

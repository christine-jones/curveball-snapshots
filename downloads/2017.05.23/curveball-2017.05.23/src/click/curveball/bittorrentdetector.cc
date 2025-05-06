/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017 and in
 * part by a grant from the United States Department of State.
 * The opinions, findings, and conclusions stated herein are those
 * of the authors and do not necessarily reflect those of the United
 * States Department of State.
 *
 * Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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
#include "bittorrentdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


BitTorrentDetector::BitTorrentDetector() : SentinelDetector(8)
{
    // defaults to 6881 (BitTorrent)
    _port = 6881;
}

BitTorrentDetector::~BitTorrentDetector()
{
}

void *
BitTorrentDetector::cast(const char *name)
{
    if (strcmp(name, "BitTorrentDetector") == 0)
        return (BitTorrentDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

SentinelDetector::Packet_Action
BitTorrentDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // flow is member of _flow_table
    if (entry != NULL) {

        if (entry->state() == FLOW_STATE_SENTINEL) {
            return process_bittorrent_data_packet(p, entry);
        }

        if (entry->state() == FLOW_STATE_SEGMENT) {
            return process_sentinel_segment(p, entry);
        }

        // packet is redirected to the curveball system
        assert(entry->state() == FLOW_STATE_REDIRECT);
        entry->set_active();
        return FORWARD_CURVEBALL;
    }

    entry = get_syn_flow(flow_key);

    // flow is member of _syn_table
    if (entry != NULL) {
        assert(entry->state() == FLOW_STATE_ACK);
        process_client_ack(p, flow_key, entry);
        return FORWARD_NON_CURVEBALL;
    }

    // flow not a member of _syn_table or _flow_table
    return FORWARD_NON_CURVEBALL;
}

SentinelDetector::Packet_Action
BitTorrentDetector::process_bittorrent_data_packet(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    // The BitTorrent sentinel is contained within the first 8 bytes
    // of the first client-side data packet.

    const int offset_to_sentinel = 0;
    const int required_length = offset_to_sentinel + _sentinel_length;

    // partial data packet; handle sentinel segment
    if (nbytes < required_length ||
        ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        return process_sentinel_segment(p, entry);
    }

    // packet contains curveball sentinel and
    // the decoy host has not been blacklisted
    if (sentinel_packet(flow_identifier,
                        (const char *)data + offset_to_sentinel,
                        _sentinel_length) &&
        !is_blacklisted(flow_identifier.daddr())) {

        entry->set_state(FLOW_STATE_REDIRECT);
        entry->set_active();

        if (_udp_port > 0) {
            generate_udp_notification(p, *entry,
                                      (const char *)data + offset_to_sentinel,
                                      _sentinel_length);
        }

        // annotate flow entry to packet
        p->set_anno_ptr(8, (const void *) entry);

        return INITIAL_REDIRECT;
    }

    // message does not contain curveball sentinel
    remove_flow(flow_identifier);
    return FORWARD_NON_CURVEBALL;
}

SentinelDetector::Packet_Action
BitTorrentDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    const int offset_to_sentinel = 0;
    const int required_length = offset_to_sentinel + _sentinel_length;

    // duplicate ack
    if (nbytes == 0) {
        return FORWARD_NON_CURVEBALL;
    }

    entry->set_state(FLOW_STATE_SEGMENT);
    if (!entry->add_pkt(p)) {
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    if (!entry->ready_for_sentinel_check(required_length)) {
        return FORWARD_NON_CURVEBALL;
    }

    char buf[_sentinel_length];
    entry->construct_sentinel_buf((char *)&buf, _sentinel_length,
                                                offset_to_sentinel + 1);

    if (!sentinel_packet(flow_identifier, (char *)&buf, _sentinel_length)) {
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    if (is_blacklisted(flow_identifier.daddr())) {
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    entry->set_state(FLOW_STATE_REDIRECT);
    entry->set_active();

    if (_udp_port > 0) {
        generate_udp_notification(p, *entry, buf, _sentinel_length);
    }

    // annotate flow entry to packet
    p->set_anno_ptr(8, (const void *) entry);

    return INITIAL_REDIRECT;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(BitTorrentDetector)

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

// prints out the sentinel for inspection-by-eyeball
// #define NEW_SENTINEL_TEST yes

#include <click/config.h>
#include "tlsflowdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


TLSFlowDetector::TLSFlowDetector() : SentinelDetector(8)
{
    // defaults to 443 (TLS)
    _port = 443;
}

TLSFlowDetector::~TLSFlowDetector()
{
}

void *
TLSFlowDetector::cast(const char *name)
{
    if (strcmp(name, "TLSFlowDetector") == 0)
        return (TLSFlowDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

SentinelDetector::Packet_Action
TLSFlowDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // flow is member of _flow_table
    if (entry != NULL) {

	if (entry->state() == FLOW_STATE_IGNORED) {
	    return FORWARD_NON_CURVEBALL;
	}
	entry->set_active();

        // an entry exists in SENTINEL state, a TLS Hello packet is expected
        if (entry->state() == FLOW_STATE_SENTINEL) {
            return process_tls_client_hello(p, entry);
        }

        // an entry exists in SEGMENT state, a TLS Hello segment is expected
        if (entry->state() == FLOW_STATE_SEGMENT) {
            assert(!_disable_segment_processing);
            return process_sentinel_segment(p, entry);
        }

        // packet is redirected to the curveball system
        assert(entry->state() == FLOW_STATE_REDIRECT);
        return FORWARD_CURVEBALL;
    }

    entry = get_syn_flow(flow_key);

    // flow is member of _syn_table
    if (entry != NULL) {

	// I'm not sure whether flows in the syn table can be in the
	// IGNORED state, but better safe than sorry.
	if (entry->state() == FLOW_STATE_IGNORED) {
	    // click_chatter("ignored syn_flow");
	    return FORWARD_NON_CURVEBALL;
	}

        assert(entry->state() == FLOW_STATE_ACK);
        process_client_ack(p, flow_key, entry);
        return FORWARD_NON_CURVEBALL;
    }

    // flow not a member of _syn_table or _flow_table
    return FORWARD_NON_CURVEBALL;
}

SentinelDetector::Packet_Action
TLSFlowDetector::process_tls_client_hello(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier = IPFlowID(p);

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.a
    // The Curveball sentinel is contained within the random number field
    // of the TLS Hello packet, bytes 16--44 of the payload.

    const int offset_to_sentinel = 15;
    const int max_sentinel_length = 28;
    const int required_length = offset_to_sentinel + max_sentinel_length;

    // Partial TLS client hello message; handle sentinel segments.
    if (nbytes < required_length ||
	    ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        if (_disable_segment_processing) {

	    /*
	    if (nbytes < required_length) {
		click_chatter("TLSFlowDetector::process_tls_client_hello: "
			"discarding short hello %d < %d",
			nbytes, required_length);
	    }
	    else {
		click_chatter("TLSFlowDetector::process_tls_client_hello: "
			"discarding ooo hello %d != %d",
			ntohl(p->tcp_header()->th_seq), entry->isn() + 1);
	    }
	    */

            remove_flow(flow_identifier);
            return FORWARD_NON_CURVEBALL;
        }

        return process_sentinel_segment(p, entry);
    }

    // Not a TLS client hello message.
    if (data[0] != 0x16 || data[5] != 0x01) {
        //click_chatter("TLSFlowDetector::process_tls_client_hello: "
        //              "TLS client hello message expected.");
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    // TLS Client Hello message contains Curveball sentinel
    // and the decoy host has not been blacklisted
    if (sentinel_packet(flow_identifier,
                        (const char *)data + offset_to_sentinel,
                        max_sentinel_length) &&
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

    // Message does not contain Curveball sentinel.
    remove_flow(flow_identifier);
    return FORWARD_NON_CURVEBALL;
}

SentinelDetector::Packet_Action
TLSFlowDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier = IPFlowID(p);

    const int offset_to_sentinel = 15;
    const int max_sentinel_length = 28;
    const int required_length = offset_to_sentinel + max_sentinel_length;

    // duplicate ack
    if (nbytes == 0) {
        return FORWARD_NON_CURVEBALL;
    }

    // too far into flow; no longer able to check for sentinel
    if (_max_sentinel_offset != 0 &&
        ntohl(p->tcp_header()->th_seq) > (entry->isn() + _max_sentinel_offset))
    {
        remove_flow(flow_identifier);
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

    char buf[max_sentinel_length];
    entry->construct_sentinel_buf((char *)&buf, max_sentinel_length,
                                                offset_to_sentinel + 1);

    if (!sentinel_packet(flow_identifier, (char *)&buf, max_sentinel_length)) {
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

void
TLSFlowDetector::process_tls_server_hello(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x02 in the 6th payload byte --- Handshake type is Client Hello.
    // The random number field of the TLS Hello packet are bytes
    // 16--44 of the payload.

    const int offset_to_random = 15;
    const int random_length = 28;
    const int required_length = offset_to_random + random_length;

    assert(!entry->proto_ack());

    // check for sufficient bytes
    if (nbytes < required_length) {
        return;
    }

    // check if packet is a TLS server hello message
    if (data[0] != 0x16 || data[5] != 0x02) {
        return;
    }

    entry->set_proto_ack();

    if (_encoder) {
        String random((const char *)(data + offset_to_random), random_length);
        _encoder->tls_established(IPFlowID(p, true), random);

    } else {
        click_chatter("TLSFlowDetector::process_tls_server_hello: "
                      "DR2DPEncoder not configured");
    }
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(TLSFlowDetector)

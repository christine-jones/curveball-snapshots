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
#include "httpflowdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS

char
fromhex(char c)
{
    if (isxdigit(c)) {
        if (isdigit(c)) {
            c -= '0';
        } else {
            c = tolower(c);
            c = c - 'a' + 10;
        }

    } else {
        c = 0;
    }

    return c;
}

void
unhexlify(const char *str, char *hex_str, int hex_len)
{
    assert((hex_len > 0) && (hex_len % 2 == 0));

    for (int i = 0; i < hex_len; ++i) {
        hex_str[i] = fromhex(str[2 * i + 1]) + 16 * fromhex(str[2 * i]);
    }
}

HTTPFlowDetector::HTTPFlowDetector() : SentinelDetector(8)
{
    // defaults to 80 (HTTP)
    _port = 80;
}

HTTPFlowDetector::~HTTPFlowDetector()
{
}

void *
HTTPFlowDetector::cast(const char *name)
{
    if (strcmp(name, "HTTPFlowDetector") == 0)
        return (HTTPFlowDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

SentinelDetector::Packet_Action
HTTPFlowDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // flow is member of _flow_table
    if (entry != NULL) {

        // an entry exists in SENTINEL state, an HTTP request is expected
        if (entry->state() == FLOW_STATE_SENTINEL) {
            return process_http_data_packet(p, entry);
        }

        // an entry exists in SEGMENT state, an HTTP request segment is expected
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

    // flow not a mbmer of _syn_table of _flow_table
    return FORWARD_NON_CURVEBALL;
}

SentinelDetector::Packet_Action
HTTPFlowDetector::process_http_data_packet(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    if (ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        return process_sentinel_segment(p, entry);
    }

    String pkt_str((const char *)data, nbytes);
    String start_of_msg_str("GET");
    String end_of_msg_str("\r\n\r\n");
    int end_of_msg;

    if (pkt_str.length() < start_of_msg_str.length()) {
        return process_sentinel_segment(p, entry);
    }

    if (pkt_str.find_left(start_of_msg_str) != 0) {
        click_chatter("HTTPFlowDetector::process_http_data_packet: "
                      "packet does not begin with GET");
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    if ((end_of_msg = pkt_str.find_left(end_of_msg_str)) == -1) {
        return process_sentinel_segment(p, entry);
    }

    end_of_msg = end_of_msg + end_of_msg_str.length();

    String sentinel;
    process_get_message(flow_identifier,
                        pkt_str.substring(0, end_of_msg),
                        sentinel);

    if (sentinel.empty()) {
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
        generate_udp_notification(p, *entry,
                                  sentinel.data(), sentinel.length());
    }

    // annotate flow entry to packet
    p->set_anno_ptr(8, (const void *) entry);

    return INITIAL_REDIRECT;
}

SentinelDetector::Packet_Action
HTTPFlowDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    // duplicate ack
    if (nbytes == 0) {
        return FORWARD_NON_CURVEBALL;
    }

    entry->set_state(FLOW_STATE_SEGMENT);
    entry->maintain_segment_buffer();
    if (!entry->add_pkt(p)) {
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    String start_of_msg_str("GET");
    String end_of_msg_str("\r\n\r\n");

    if (!entry->ready_for_sentinel_check(end_of_msg_str)) {
        return FORWARD_NON_CURVEBALL;
    }

    if (entry->segment_buffer().find_left(start_of_msg_str) != 0) {
        click_chatter("HTTPFlowDetector::process_sentinel_segment: "
                      "data does not begin with GET");
        remove_flow(flow_identifier);
        return FORWARD_NON_CURVEBALL;
    }

    String sentinel;
    process_get_message(flow_identifier, entry-> segment_buffer(), sentinel);

    if (sentinel.empty()) {
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
        generate_udp_notification(p, *entry,
                                  sentinel.data(), sentinel.length());
    }

    // annotate flow entry to packet
    p->set_anno_ptr(8, (const void *) entry);

    return INITIAL_REDIRECT;
}

void
HTTPFlowDetector::process_get_message(
    const IPFlowID &flow_key, const String &get_msg, String &sentinel)
{
    String cookie_str("\r\nCookie: ");
    int cookie_start, cookie_end;

    cookie_start = get_msg.find_left(cookie_str);

    while (cookie_start != -1) {
        cookie_start = cookie_start + cookie_str.length();

        if ((cookie_end = get_msg.find_left("\r\n", cookie_start)) == -1) {
            click_chatter("HTTPFlowDetector::process_get_msg: "
                          "failed to find end of cookie field");
            return;
        }

        int cookie_length = cookie_end - cookie_start;

        process_cookie_field(flow_key,
                             get_msg.substring(cookie_start, cookie_length),
                             sentinel);

        if (!sentinel.empty()) {
            return;
        }

        cookie_start = get_msg.find_left(cookie_str, cookie_end);
    }
}

void
HTTPFlowDetector::process_cookie_field(
    const IPFlowID &flow_key, const String &cookie_field, String &sentinel)
{
    bool end_of_cookie_field = false;
    int cookie_start = 0, cookie_end;

    while(!end_of_cookie_field) {

        if ((cookie_end = cookie_field.find_left("; ", cookie_start)) == -1) {
            cookie_end = cookie_field.length();
            end_of_cookie_field = true;
        }

        int this_cookie_start = cookie_start;

        // add two characters to account for "; " cookie delineator
        cookie_start = cookie_end + 2;

        int value_start, value_end = cookie_end;
        if ((value_start =
                 cookie_field.find_left("=", this_cookie_start)) == -1) {
            click_chatter("HTTPFlowDetector::process_cookie: "
                          "failed to divde name/value pair");
            continue;
        }

        // advance past '=' character
        value_start += 1;
        int value_length = value_end - value_start;

        int sentinel_length = 2 * _sentinel_length;

        if (value_length < sentinel_length) {
            // value field too small to contain sentinel
            continue;
        }

        if (sentinel_packet(flow_key,
                            cookie_field.data() + value_start,
                            sentinel_length)) {
            sentinel = cookie_field.substring(value_start, sentinel_length);
            return;
        }
    }
}

bool
HTTPFlowDetector::sentinel_packet(
    const IPFlowID &flow_key, const char *buf, int len)
{
    if (seen_flow(flow_key, buf, len)) {
        click_chatter("HTTPFlowDetector::sentinel_packet: "
                      "ignoring already seen flow");
        return false;
    }

    if (string_sentinel(buf, len)) {
        click_chatter("HTTPFlowDetector::sentinel_packet: "
                      "packet contains valid sentinel");
        return true;
    }

    if (len != (2 * _sentinel_length)) {
        return false;
    }

    char hex_str[_sentinel_length];
    unhexlify(buf, hex_str, _sentinel_length);

    if (seen_flow(flow_key, hex_str, _sentinel_length)) {
        click_chatter("HTTPFlowDetector::sentinel_packet: "
                      "ignoring already seen flow");
        return false;
    }

    if (filter_sentinel(hex_str, _sentinel_length)) {
        click_chatter("HTTPFlowDetector::sentinel_packet: "
                      "packet contains valid sentinel");
        return true;
    }

    return false;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(HTTPFlowDetector)

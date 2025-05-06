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
#include "tlshellosentineldetector.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


TLSHelloSentinelDetector::TLSHelloSentinelDetector()
    : _flow_filter((FlowFilter *)NULL)
{
}

TLSHelloSentinelDetector::~TLSHelloSentinelDetector()
{
}

void *
TLSHelloSentinelDetector::cast(const char *name)
{
    if (strcmp(name, "TLSHelloSentinelDetector") == 0)
        return (TLSHelloSentinelDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

int
TLSHelloSentinelDetector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "FLOW", cpkP+cpkM, cpElement, &_flow_filter,
                        "SENTINEL", 0, cpString, &_sentinel,
                        cpEnd);
}

int
TLSHelloSentinelDetector::initialize(ErrorHandler *errh)
{
    if (!_flow_filter || !_flow_filter->cast("FlowFilter")) {
        errh->warning("%s: FlowFilter element is missing or has the wrong type",
                      name().c_str());
        _flow_filter = (FlowFilter *)NULL;
    }

    return 0;
}

void
TLSHelloSentinelDetector::push_packet(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);
    assert(p->has_transport_header());
    assert(tls_hello_packet(p));

    // Packet contains Curveball sentinel; requires redirection.
    if (redirect_packet(p)) {

        // Update configured flow filter element with extracted flow key.
        if (_flow_filter != NULL) {
            _flow_filter->add_flow(IPFlowID(p));
        }

        output(0).push(p);

    // Non-Curveball packet to be forwarded as normal.
    } else {
        output(1).push(p);
    }
}

bool
TLSHelloSentinelDetector::tls_hello_packet(Packet *p)
{
    // TLS packets are destined to port 443.

    if (ntohs(p->tcp_header()->th_dport) != 443) {
        return false;
    }

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.

    return ((nbytes >= 6) && (data[0] == 0x16 && data[5] == 0x01));
}

bool
TLSHelloSentinelDetector::redirect_packet(Packet *p)
{
    // Check string sentinel first, if one is configured.
    if (_sentinel.length() > 0 && string_sentinel(p)) {
            return true;
    }

    // The Curveball sentinel is contained within the random number
    // field of the TLS Hello packet, bytes 16--44 of the payload.

    const int offset_to_sentinel = 15;
    const int sentinel_length = 8;
    const int required_length = offset_to_sentinel + sentinel_length;

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if (nbytes < required_length) {
        click_chatter("TLSHelloSentinelDetector::redirect_packet: "
                      "Packet too small to contain sentinel value.");
        return false;
    }

    const char *sentinel_buf = (const char *)(data + offset_to_sentinel);
    /*
    click_chatter("Checking sentinel");
    String hexed;
    for (int i = 0; i < 8; i++) {
    	char b = sentinel_buf[i] >> 4;
    	hexed += (char)(b > 9 ? b + 0x37 : b + 0x30);
    	b = sentinel_buf[i] & 0xf;
    	hexed += (char)(b > 9 ? b + 0x37 : b + 0x30);
    }
    click_chatter("%s", hexed.c_str());
    click_chatter("Length = %d", sentinel_length);
    */
    if ((_sentinels == NULL) ||
        (!_sentinels->member(sentinel_buf, sentinel_length))) {
        // packet does not contain valid Curveball sentinel
        return false;
    }

    click_chatter("TLSHelloSentinelDetector::redirect_packet: "
                  "Packet contains valid sentinel.");
    return true;
}

bool
TLSHelloSentinelDetector::string_sentinel(Packet *p)
{
    // The Curveball sentinel is contained within the random number
    // field of the TLS Hello packet, starting at byte 16 of the payload.

    const int offset_to_sentinel = 15;
    const int required_length = offset_to_sentinel + _sentinel.length();

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if (nbytes < required_length) {
        click_chatter("TLSHelloSentinelDetector::string_sentinel: "
                      "Packet too small to contain sentinel value.");
        return false;
    }

    const char *sentinel_buf = (const char *)(data + offset_to_sentinel);
    if (String(sentinel_buf, _sentinel.length()) != _sentinel) {
        // packet does not contain valid Curveball sentinel
        return false;
    }

    click_chatter("IncrementalTLSDetector::string_sentinel: "
                  "Packet contains valid sentinel.");
    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(TLSHelloSentinelDetector)

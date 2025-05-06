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
#include "tlshellofilter.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


TLSHelloFilter::TLSHelloFilter()
{
}

TLSHelloFilter::~TLSHelloFilter()
{
}

void
TLSHelloFilter::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are non-Curveball.
    if (non_first_fragment(p)) {
        output(2).push(p);
        return;
    }

    assert(p->has_transport_header());

    // Non-Curveball packet.
    if (!tls_protocol(p)) {
        output(2).push(p);

    // Possible Curveball sentinel packet.
    } else if (tls_hello(p)) {
        output(0).push(p);

    // Possible Curveball non-sentinel packets.
    } else {
        output(1).push(p);
    }
}

bool
TLSHelloFilter::non_first_fragment(Packet *p)
{
    return (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header()));
}

bool
TLSHelloFilter::tls_protocol(Packet *p)
{
    // TLS packets are destined to port 443.

    return (ntohs(p->tcp_header()->th_dport) == 443);
}

bool
TLSHelloFilter::tls_hello(Packet *p)
{
    assert(tls_protocol(p));

    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.

    return ((nbytes >= 6) && (data[0] == 0x16 && data[5] == 0x01));
}


CLICK_ENDDECLS
EXPORT_ELEMENT(TLSHelloFilter)

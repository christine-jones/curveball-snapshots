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
#include "fragidentifier.hh"
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


void
FragFlowTable::add_flow(const IPFlowID &flow_key)
{
    // Check that a flow entry does not already exist.
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        click_chatter("FragFlowTable::add_flow: flow entry already exists %s",
                      flow_key.unparse().c_str());
        return;
    }

    // Insert entry into flow table.
    _flow_table.set(flow_key, FragFlowEntry());
}

void
FragFlowTable::remove_flow(const IPFlowID &flow_key)
{
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        _flow_table.erase(flow_key);
    }
}


FragIdentifier::FragIdentifier()
    : _frag_sentinel(true), _frag_all(false), _pkt_offset(0), _flow_table()
{
}

FragIdentifier::~FragIdentifier()
{
}

int
FragIdentifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "FRAGMENT_SENTINEL", 0, cpBool, &_frag_sentinel,
                        "FRAGMENT_ALL", 0, cpBool, &_frag_all,
                        "PACKET_OFFSET", 0, cpUnsigned, &_pkt_offset,
                        cpEnd);
}

void
FragIdentifier::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are simply forwarded.
    // Although, we really shouldn't receive any fragments at this point!
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        click_chatter("Recevied IP packet fragment.");
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());
    unsigned int port = ntohs(p->tcp_header()->th_dport);

    // TLS packet
    if (port == 443) {
        process_packet(p, tls_sentinel_packet(p));

    // HTTP packet
    } else if (port == 80) {
        process_packet(p, http_sentinel_packet(p));

    // all other packets bypass the fragmenter
    } else {
        output(0).push(p);
    }
}

void
FragIdentifier::process_packet(Packet *p, bool sentinel_packet)
{
    IPFlowID flow_key = IPFlowID(p);

    if (syn_packet(p)) {
        _flow_table.add_flow(flow_key);
        output(0).push(p);
        return;
    }

    FragFlowEntry *entry = _flow_table.get_flow(IPFlowID(flow_key));
    if (entry == NULL) {
        output(0).push(p);
        return;
    }

    if (sentinel_packet) {
        entry->set_sentinel_pkt_seen();
    }

    if (_frag_all && entry->sentinel_pkt_seen()) {
        click_chatter("fragmenting packet");
        output(1).push(p);
        return;
    }

    if (sentinel_packet && _frag_sentinel) {
        click_chatter("fragmenting sentinel packet");
        _flow_table.remove_flow(flow_key);
        output(1).push(p);
        return;
    }
    
    if (!entry->sentinel_pkt_seen()) {
        output(0).push(p);
        return;
    }
    assert(!_frag_sentinel);

    if (_pkt_offset == 0) {
        click_chatter("packet offset not set");
        _flow_table.remove_flow(flow_key);
        output(0).push(p);
        return;
    }

    entry->pkt_seen();

    if (entry->num_pkts_seen() == _pkt_offset) {
        click_chatter("fragmenting non-sentinel packet");
        _flow_table.remove_flow(flow_key);
        output(1).push(p);
        return;
    }

    output(0).push(p);
}

bool
FragIdentifier::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

bool
FragIdentifier::tls_sentinel_packet(Packet *p)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.

    return ((nbytes >= 6) && (data[0] == 0x16 && data[5] == 0x01));
}

bool
FragIdentifier::http_sentinel_packet(Packet *p)
{
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

CLICK_ENDDECLS
EXPORT_ELEMENT(FragIdentifier)

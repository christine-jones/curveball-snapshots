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
#include "flowtable.hh"
#include <click/packet.hh>
#include <click/vector.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


bool
FlowEntry::add_pkt(Packet *p)
{
    Packet *q = WritablePacket::make(p->headroom(), p->data(), p->length(), 0);
    if (q == NULL) {
        click_chatter("FlowEntry::add_pkt: failed to make packet");
        return false;
    }

    // set network and transport headers
    assert(q->length() > sizeof(click_ip));

    const click_ip *ip_hdr = (const click_ip *)(q->data());
    unsigned int ip_hlen = ip_hdr->ip_hl << 2;

    q->set_network_header(q->data());
    q->set_transport_header(q->data() + ip_hlen);

    // insert new packet into packet segment buffer
    if (_pktbuf == NULL) {
        q->set_prev((Packet *)NULL);
        q->set_next((Packet *)NULL);
        _pktbuf = q;
        return true;
    }

    Packet *pkt, *next_pkt;
    for (pkt = _pktbuf, next_pkt = _pktbuf->next();
         next_pkt != NULL;
         pkt = next_pkt, next_pkt = next_pkt->next());

    q->set_next((Packet *)NULL);
    q->set_prev(pkt);
    pkt->set_next(q);

    if (_maintain_buffer) {
        build_segment_buffer();
    }

    return true;
}

bool
FlowEntry::ready_for_sentinel_check(int len)
{
    uint32_t lsn = _isn + len;

    uint32_t prev_seq = 0;
    while (_seq_ptr != prev_seq) {
        prev_seq = _seq_ptr;

        if (_seq_ptr >= lsn) {
            return true;
        }

        Packet *p = _pktbuf;
        while (p != NULL) {
            int nbytes = p->end_data() - (p->transport_header() +
                                          (p->tcp_header()->th_off << 2));

            uint32_t p_fseq = ntohl(p->tcp_header()->th_seq);
            uint32_t p_lseq = ((p_fseq + nbytes) - 1);

            if ((_seq_ptr >= (p_fseq - 1)) && (_seq_ptr < p_lseq)) {
                _seq_ptr = p_lseq;
            }

            p = p->next();
        }
    }

    return false;
}

bool
FlowEntry::ready_for_sentinel_check(const String &end_str)
{
    int end_index;
    if ((end_index = _segment_buffer.find_left(end_str)) == -1) {
        return false;
    }

    int desired_length = end_index + end_str.length();
    _segment_buffer = _segment_buffer.substring(0, desired_length);

    return true;
}

void
FlowEntry::construct_sentinel_buf(char *buf, int len, int offset)
{
    uint32_t start_seq = _isn + offset;
    uint32_t end_seq = (start_seq + len) - 1;

    if (_seq_ptr < end_seq) {
        click_chatter("FlowEntry::construct_sentinel_buf: "
                      "insufficient segment length to reconstruct sentinel");
        return;
    }

    Packet *p = _pktbuf;
    while (p != NULL) {
        const uint8_t *data = p->transport_header() +
                              (p->tcp_header()->th_off << 2);
        int nbytes = p->end_data() - data;

        uint32_t p_fseq = ntohl(p->tcp_header()->th_seq);
        uint32_t p_lseq = ((p_fseq + nbytes) - 1);
        assert(p_fseq <= p_lseq);

        if (p_fseq <= end_seq && p_lseq >= start_seq) {
            int copy_to_offset =   (p_fseq <= start_seq)?
                                       0 : (p_fseq - start_seq);
            int copy_from_offset = (p_fseq >= start_seq)?
                                       0 : (start_seq - p_fseq);
            int copy_bytes = (((p_lseq > end_seq)  ? end_seq   : p_lseq) -
                              ((p_fseq < start_seq)? start_seq : p_fseq)) + 1;

            memcpy(buf + copy_to_offset, data + copy_from_offset, copy_bytes);
        }

        p = p->next();
    }
}

void
FlowEntry::release_pkt_buffer()
{
    Packet *pkt = _pktbuf;
    while (pkt != NULL) {
        Packet *p = pkt;
        pkt = pkt->next();

        p->kill();
    }
}

void
FlowEntry::build_segment_buffer()
{
    uint32_t curr_seq = _isn + _segment_buffer.length();
    uint32_t prev_seq = 0;

    while (curr_seq != prev_seq) {
        prev_seq = curr_seq;

        Packet *p = _pktbuf;
        while(p != NULL) {
            int nbytes = p->end_data() - (p->transport_header() +
                                         (p->tcp_header()->th_off << 2));

            uint32_t p_fseq = ntohl(p->tcp_header()->th_seq);
            uint32_t p_lseq = ((p_fseq + nbytes) - 1);

            if ((curr_seq >= (p_fseq - 1)) && (curr_seq < p_lseq)) {

                const uint8_t *data = p->transport_header() +
                                     (p->tcp_header()->th_off << 2);

                int start_offset = curr_seq - (p_fseq - 1);
                int copy_length  = nbytes - start_offset;
                _segment_buffer.append((const char *)data + start_offset,
                                       copy_length);

                curr_seq = p_lseq;
            }

            p = p->next();
        }
    }
}


FlowTable::FlowTable()
    : _flow_table(FlowEntry())
{
}

FlowTable::~FlowTable()
{
}

void
FlowTable::add_flow(Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);
    assert(p->has_transport_header());

    IPFlowID flow_key = IPFlowID(p);

    // Check that a flow entry does not already exist.
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        //click_chatter("FlowTable::add_flow: flow entry already exists %s",
        //              flow_key.unparse().c_str());
        return;
    }

    // Instantiate new flow entry.
    FlowEntry new_entry(ntohl(p->tcp_header()->th_seq), flow_key);

    // Record any TCP options.
    const int option_offset = 20;
    const int option_length = (p->tcp_header()->th_off << 2) - option_offset;
    if (option_length > 0) {
        const uint8_t *data = p->transport_header() + option_offset;
        new_entry.set_tcp_syn_options(String((const char *)data,
                                      option_length));
    }

    // record ehternet information
    assert(p->has_mac_header());
    assert(p->headroom() >= p->mac_header_length());

    if (p->mac_header_length() == sizeof(click_ether)) {
        const click_ether * ether_hdr =
            (const click_ether *)(p->data() - sizeof(click_ether));

        new_entry.set_ethernet_addrs(EtherAddress(ether_hdr->ether_shost),
                                     EtherAddress(ether_hdr->ether_dhost));

    } else if (p->mac_header_length() == sizeof(click_ether_vlan)) {
        const click_ether_vlan * ether_hdr = 
            (const click_ether_vlan *)(p->data() - sizeof(click_ether_vlan));

        new_entry.set_ethernet_addrs(EtherAddress(ether_hdr->ether_shost),
                                     EtherAddress(ether_hdr->ether_dhost));

        new_entry.set_vlan_tag(ether_hdr->ether_vlan_tci);

    } else {
        click_chatter("FlowTable::add_flow: unknown ether type");
    }

    // Insert entry into flow table.
    _flow_table.set(flow_key, new_entry);
}

void
FlowTable::add_entry(const IPFlowID &flow_key, FlowEntry *entry)
{
    assert(_flow_table.set(flow_key, *entry));
}

void
FlowTable::remove_flow(const IPFlowID &flow_key)
{
    // removes the flow with the given key; nothing if flow not in table
    // mark the flow as being removed: make it inactive,
    // and make it non-redirected, but DO NOT actually
    // delete it from the table.  This avoids a potential
    // TOCTOU bug when things are removed by one thread
    // while they are still referenced by another
    //
    FlowEntry *entry = get_flow(flow_key);
    if (entry == NULL) {
       return;
    }

    entry->set_state(FLOW_STATE_IGNORED);
    entry->set_inactive();
}

void
FlowTable::expunge_flow(const IPFlowID &flow_key)
{
    // really remove the flow the table
    _flow_table.erase(flow_key);
}

void
FlowTable::remove_inactive_flows()
{
    ssize_t old_size = _flow_table.size();
    Vector<IPFlowID> inactive_flows;

    inactive_flows.reserve(old_size);

    HashTable<IPFlowID, FlowEntry>::iterator end_of_flows = _flow_table.end();

    // identify inactive flows; inactive flows cannot be removed during this
    // iteration of the flow table because the iterator would become invalid
    for(HashTable<IPFlowID, FlowEntry>::iterator flow = _flow_table.begin();
        flow != end_of_flows;
        ++flow) {

        FlowEntry &flow_entry = flow.value();

        if (flow_entry.active() == false) {
            inactive_flows.push_back(flow.key());
        }

        // reset all flows as inactive for the next time interval
        flow_entry.set_inactive();
    }

    for (Vector<IPFlowID>::iterator flow = inactive_flows.begin();
         flow != inactive_flows.end();
         ++flow) {

        expunge_flow(*flow);
    }

    ssize_t new_size = _flow_table.size();

    click_chatter("FlowEntry::remove_inactive: %ld -> %ld (deleted %ld)",
	    old_size, new_size, old_size - new_size);
}

String
FlowTable::table_to_str() const
{
    String table;

    table  = "---------- Flow Table ----------\n";
    for(HashTable<IPFlowID, FlowEntry>::const_iterator flow =
                                                       _flow_table.begin();
        flow != _flow_table.end();
        ++flow) {
        table += flow.key().unparse();
        table += '\n';
    }
    table += "--------------------------------\n";

    return table;
}


CLICK_ENDDECLS
ELEMENT_PROVIDES(FlowTable)

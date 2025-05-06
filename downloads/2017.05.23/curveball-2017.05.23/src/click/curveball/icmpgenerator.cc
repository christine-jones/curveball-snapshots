/* $Id$
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 * Copyright 2011 - Raytheon BBN Technologies - All Rights Reserved
 */

#include <click/config.h>
#include "icmpgenerator.hh"
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


bool
ICMPFlowEntry::generate_icmp()
{
    if (_gen_count == 0 && _pause_count == 0) {
        return false;
    }

    if (_gen_count > 0) {
        _gen_count--;
        return true;
    }

    assert(_pause_count > 0);

    _pause_count--;
    if (_pause_count == 0) {
        _gen_count = _num_generated;
        _pause_count = _pause_interval;
    }

    return false;
}

void
ICMPFlowTable::add_flow(const IPFlowID & flow_key,
                        unsigned int num_generated,
                        unsigned int pause_interval)
{
    // check that a flow entry does not already exist
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        click_chatter("ICMPFlowTable::add_flow: flow entry already exists %s",
                      flow_key.unparse().c_str());
        return;
    }

    // insert entry into flow table
    _flow_table.set(flow_key, ICMPFlowEntry(num_generated, pause_interval));
}

void
ICMPFlowTable::remove_flow(const IPFlowID & flow_key)
{
    if (_flow_table.find(flow_key) != _flow_table.end()) {
        _flow_table.erase(flow_key);
    }
}


ICMPGenerator::ICMPGenerator()
    : _num_generated(1), _pause_interval(0), _initial_pause(0),
      _reverse(true), _flow_table()
{
}

ICMPGenerator::~ICMPGenerator()
{
}

int
ICMPGenerator::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "NUM_GENERATED", 0, cpUnsigned, &_num_generated,
                        "PAUSE_INTERVAL", 0, cpUnsigned, &_pause_interval,
                        "INITIAL_PAUSE", 0, cpUnsigned, &_initial_pause,
                        "REVERSE", 0, cpBool, &_reverse,
                        cpEnd);
}

void
ICMPGenerator::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // non-first packet fragments are simply forwarded.
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        click_chatter("Recevied IP packet fragment.");
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());
    unsigned int src_port = ntohs(p->tcp_header()->th_sport);
    unsigned int dst_port = ntohs(p->tcp_header()->th_dport);

    // tls packet
    if (src_port == 443 || dst_port == 443) {
        bool reverse = (src_port == 443);
        bool sentinel = false;
        if (!reverse) {
            sentinel = tls_sentinel_packet(p);
        }

        process_packet(p, reverse, sentinel);

    // http packet
    } else if (src_port == 80 || dst_port == 80) {
        bool reverse = (src_port == 80);
        bool sentinel = false;
        if (!reverse) {
            sentinel = http_sentinel_packet(p);
        }

        process_packet(p, reverse, sentinel);

    // all other packets bypass the icmp generator
    } else {
        output(0).push(p);
    }
}

void
ICMPGenerator::process_packet(Packet *p, bool reverse, bool sentinel_packet)
{
    if (reverse) {
        assert(!sentinel_packet);
    }

    IPFlowID flow_key = IPFlowID(p);

    if (syn_packet(p)) {
        if (!reverse) {
            _flow_table.add_flow(flow_key, _num_generated, _pause_interval);
        }
        output(0).push(p);
        return;
    }

    ICMPFlowEntry * entry;
    if (!reverse) {
        entry = _flow_table.get_flow(flow_key);
    } else {
        entry = _flow_table.get_flow(flow_key.reverse());
    }
    if (entry == NULL) {
        output(0).push(p);
        return;
    }

    // dont't generate icmp until after sentinel packet seen
    if (!sentinel_packet && !entry->sentinel_pkt_seen()) {
        output(0).push(p);
        return;
    }

    if (sentinel_packet && !entry->sentinel_pkt_seen()) {
        entry->set_sentinel_pkt_seen();
        output(0).push(p);
        return;
    }

    entry->pkt_seen(reverse);

    if (_reverse != reverse) {
        output(0).push(p);
        return;
    }

    if (entry->num_pkts_seen(reverse) <= _initial_pause) {
        output(0).push(p);
        return;
    }

    if (!entry->generate_icmp()) {
        output(0).push(p);
        return; 
    }

    click_chatter("Generating ICMP");
    output(1).push(p);
}

bool
ICMPGenerator::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

bool
ICMPGenerator::tls_sentinel_packet(Packet *p)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.

    return ((nbytes >= 6) && (data[0] == 0x16 && data[5] == 0x01));
}

bool
ICMPGenerator::http_sentinel_packet(Packet *p)
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
EXPORT_ELEMENT(ICMPGenerator)

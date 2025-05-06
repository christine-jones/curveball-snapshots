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
#include "sentineldetector.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <unistd.h>
CLICK_DECLS


SentinelDetector::SentinelDetector(int sentinel_length)
    : _sentinels(NULL),
      _sentinel_length(sentinel_length),
      _max_sentinel_offset(0),
      _disable_segment_processing(false),
      _flow_table(),
      _syn_table_one(),
      _syn_table_two(),
      _cur_syn_table(&_syn_table_one),
      _prev_syn_table(&_syn_table_two),
      _syn_table_timeout(0),
      _syn_timer(this),
      _timeout_in_sec(0),
      _flow_timer(this),
      _encoder(NULL),
      _port(0),
      _forward_reverse(false),
      _udp_port(0)
{
}

SentinelDetector::~SentinelDetector()
{
}

int
SentinelDetector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _syn_table_timeout = 20;
    _timeout_in_sec = 60;

    _max_sentinel_offset = 1000;

    return cp_va_kparse(conf, this, errh,
                    "TIMEOUT", 0, cpUnsigned, &_timeout_in_sec,
                    "PORT", 0, cpTCPPort, &_port,
                    "SENTINEL", 0, cpString, &_sentinel,
                    "ENCODER", 0, cpElement, &_encoder,
                    "SENTINEL_LENGTH", 0, cpInteger, &_sentinel_length,
                    "REVERSE", 0, cpBool, &_forward_reverse,
                    "UDP_PORT", 0, cpUDPPort, &_udp_port,
                    "UDP_SRC_ADDR", 0, cpIPAddress, &_udp_src_addr,
                    "MAX_SENTINEL_OFFSET", 0, cpUnsigned, &_max_sentinel_offset,
                    "SYN_TIMEOUT", 0, cpUnsigned, &_syn_table_timeout,
                    "DISABLE_SEGMENTS", 0, cpBool, &_disable_segment_processing,
                    cpEnd);
}

int
SentinelDetector::initialize(ErrorHandler *errh)
{
    if (!_encoder ||
        !_encoder->cast("DR2DPEncoder")) {
        _encoder = NULL;
        return errh->error("DR2DPEncoder not configured");
    }

    _syn_timer.initialize(this);
    _syn_timer.schedule_after_sec(10);

    _flow_timer.initialize(this);
    _flow_timer.schedule_after_sec(_timeout_in_sec);

    return 0;
}

void
SentinelDetector::cleanup(CleanupStage)
{
    _syn_table_one.clear();
    _syn_table_two.clear();
    _flow_table.clear();
    _seen_flows.clear();
    _syn_timer.clear();
    _flow_timer.clear();
}

#if HAVE_BATCH
void
SentinelDetector::push_batch(int port, PacketBatch *batch)
{
    Packet *current = batch;
    Packet *last = batch;

    int count = batch->count();
    int forward = 0, curveball = 0, redirect = 0;

    while (current != NULL) {
        SentinelDetector::Packet_Action
            action = process_incoming_packet(port, current);

        if (action == FORWARD_NON_CURVEBALL) {
            last = current;
            current = current->next();
            forward++;
            continue;
        }

        // action == FORWARD_CURVEBALL || INITIAL_REDIRECT

        if (current == batch) {
            batch = PacketBatch::start_head(current->next());
            current->set_next(NULL);

            if (action == FORWARD_CURVEBALL) {
                output_push_batch(0, PacketBatch::make_from_packet(current));
                curveball++;

            } else { // action == INITIAL_REDIRECT
                redirect_packet(current);
                redirect++;
            }

            current = batch;
            last = batch;
            continue;
        }

        // current != batch; action == FORWARD_CURVEBALL || INITIAL_REDIRECT

        Packet *pkt = current;
        current = current->next();
        pkt->set_next(NULL);

        if (action == FORWARD_CURVEBALL) {
            output_push_batch(0, PacketBatch::make_from_packet(pkt));
            curveball++;

        } else { // action == INITIAL_REDIRECT
            redirect_packet(pkt);
            redirect++;
        }

        last->set_next(current);
    }

    assert(count == (forward + curveball + redirect));

    if (batch != NULL) {
        batch->set_count(forward);
        batch->set_tail(last);

        // client-side packets
        if (port == 0) {
            output_push_batch(1, batch);

        // server-size packets
        } else {
            assert(port == 1);
            output_push_batch(3, batch);
        }
    }
}
#endif

void
SentinelDetector::push_packet(int port, Packet *p)
{
    SentinelDetector::Packet_Action action = process_incoming_packet(port, p);

    if (action == FORWARD_NON_CURVEBALL) {
        // client-size packets
        if (port == 0) {
            output(1).push(p);

        // server-size packets
        } else {
            assert(port == 1);
            output(3).push(p);
        }
        return;
    }

    if (action == FORWARD_CURVEBALL) {
        output(0).push(p);
        return;
    }

    assert(action == INITIAL_REDIRECT);
    redirect_packet(p);
}

SentinelDetector::Packet_Action
SentinelDetector::process_incoming_packet(int port, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are simply forwarded.
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        return FORWARD_NON_CURVEBALL;
    }

    assert(p->has_transport_header());

    // server-side communication
    if (port == 1) {
        return process_server_packet(p);
    }

    // Non-TLS packets are simply forwarded.
    if (ntohs(p->tcp_header()->th_dport) != _port) {
        return FORWARD_NON_CURVEBALL;
    }

    // client-side communication
    if (syn_packet(p)) {
        // we could check for the flow's membership in the _flow_table prior
        // to adding to the _syn_table; however, later in the flow's life we
        // always check the _flow_table first, so a duplicate in the _syn_table
        // will have no negative effect and will eventually be aged out
        add_syn_flow(p);
        return FORWARD_NON_CURVEBALL;
    }

    return process_non_syn_packet(p);
}

void
SentinelDetector::update_sentinel_filter(BloomFilter * filter)
{
    _sentinels = filter;
}

bool
SentinelDetector::syn_packet(Packet *p)
{
    return ((p->tcp_header()->th_flags & (TH_SYN | TH_ACK)) == TH_SYN);
}

void
SentinelDetector::process_client_ack(
    Packet *p, const IPFlowID &flow_key, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if (((p->tcp_header()->th_flags & (TH_SYN | TH_ACK)) == TH_ACK) &&
         (nbytes == 0)) {
        entry->set_state(FLOW_STATE_SENTINEL);

    } else {
        //click_chatter("SentinelDetector::process_client_ack: "
        //              "Invalid client ACK in TCP handshake.");
        remove_syn_flow(IPFlowID(p));
        return;
    }

    // tcp handshake complete; move flow from _syn_table to _flow_table
    _flow_table.add_entry(flow_key, entry);
     remove_syn_flow(flow_key);
}

SentinelDetector::Packet_Action
SentinelDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // flow is member of _flow_table
    if (entry != NULL) {
        assert(entry->state() != FLOW_STATE_ACK);
        remove_flow(flow_key);
        return FORWARD_NON_CURVEBALL;
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

void
SentinelDetector::update_dh_blacklist(
    const Vector<DHBlacklistEntry> & blacklist)
{
    _dh_blacklist = blacklist;
}

SentinelDetector::Packet_Action
SentinelDetector::process_server_packet(Packet *p)
{
    if (ntohs(p->tcp_header()->th_sport) != _port) {
        return FORWARD_NON_CURVEBALL;
    }

    IPFlowID flow_key = IPFlowID(p, true);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    if (entry != NULL) {
        if (entry->state() == FLOW_STATE_REDIRECT && _forward_reverse) {
            return FORWARD_CURVEBALL;
        } else {
            return FORWARD_NON_CURVEBALL;
        }
    }

    entry = get_syn_flow(flow_key);

    if (entry != NULL) {
        assert(entry->state() == FLOW_STATE_ACK);
        process_server_ack(p, entry);
        return FORWARD_NON_CURVEBALL;
    }

    return FORWARD_NON_CURVEBALL;
}

void
SentinelDetector::process_server_ack(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if ((p->tcp_header()->th_flags & TH_ACK) &&
        (ntohl(p->tcp_header()->th_ack) == (entry->isn() + 1)) &&
        (nbytes == 0)) {

        int option_offset = 20;
        int option_length = (p->tcp_header()->th_off << 2) - option_offset;
        if (option_length > 0) {
            const uint8_t *options = p->transport_header() + option_offset;
            entry->set_tcp_ack_options(String((const char *)options,
                                              option_length));
        }

        entry->set_server_ack();

    } else {
        click_chatter("TLSFLowDetector::process_server_ack: "
                      "Invalid server ACK in TCP handshake.");
    }
}

void
SentinelDetector::redirect_packet(Packet *p)
{
    assert(_encoder);
    assert(p->next() == NULL);

    FlowEntry *entry = (FlowEntry *) p->anno_ptr(8);
    assert(entry);

    bool segmented_pkt = false;
    Packet *redirect_pkt = p;

    if (entry->pktbuf() != NULL) {
        segmented_pkt = true;
        redirect_pkt = entry->pktbuf();
    }

    _encoder->redirect_flow(entry, redirect_pkt);

    // last packet segment to reconstruct the sentinel field is not forwarded,
    // but redirected to the decoy proxy only; p cloned in pktbuf
    if (segmented_pkt) {
        p->kill();
    }
}

bool
SentinelDetector::sentinel_packet(
    const IPFlowID &flow_key, const char *buf, int len)
{
    if (seen_flow(flow_key, buf, len)) {
        click_chatter("SentinelDetector::sentinel_packet: ",
                      "ignoring already seen flow");
        return false;
    }

    if (string_sentinel(buf, len) || filter_sentinel(buf, len)) {
            click_chatter("SentinelDetector::sentinel_packet: "
                          "packet contains valid sentinel");
            return true;
    }

    return false;
}

bool
SentinelDetector::filter_sentinel(const char *buf, int len)
{
    assert(len >= _sentinel_length);

    if (_sentinels == NULL) {
        click_chatter("SentinelDetector::filter_packet: "
                      "no sentinel bloom filter loaded");
        return false;
    }

    return (_sentinels->member(buf, _sentinel_length));
}

bool
SentinelDetector::string_sentinel(const char *buf, int len)
{
    if ((_sentinel.length() == 0) || (len < _sentinel.length())) {
        return false;
    }

    return (String(buf, _sentinel.length()) == _sentinel);
}

void
SentinelDetector::generate_udp_notification(const Packet *p,
                                            const FlowEntry &entry,
                                            const char *sentinel,
                                            unsigned int sentinel_len)
{
    if (_udp_port == 0) {
        click_chatter("SentinelDetector::generate_udp_notification: "
                      "No UDP-notification port specified.");
        return;
    }

    assert(p->has_network_header());
    IPFlowID flow_key(p);

    int pkt_len = sizeof(click_ether) +
                  sizeof(click_ip) +
                  sizeof(click_udp) +
                  sizeof(dr_flow_notification_msg) +
                  sentinel_len;

    WritablePacket *udp_pkt = WritablePacket::make(0, NULL, pkt_len, 0);
    if (!udp_pkt) {
        click_chatter("SentinelDetector::generate_udp_notification: "
                      "failed to allocate packet");
        return;
    }

    memset(udp_pkt->data(), 0, pkt_len);

    click_ether *ether_hdr = (click_ether *)(udp_pkt->data());
    ether_hdr->ether_type = htons(ETHERTYPE_IP);
    memcpy(&ether_hdr->ether_shost,
           entry.get_src_ethernet().data(),
           sizeof(ether_hdr->ether_shost));
    memcpy(&ether_hdr->ether_dhost,
           entry.get_dst_ethernet().data(),
           sizeof(ether_hdr->ether_dhost));

    udp_pkt->set_network_header(
        udp_pkt->data() + sizeof(click_ether), sizeof(click_ip));

    // Build the IP header.
    click_ip *ip_hdr = reinterpret_cast<click_ip *>(udp_pkt->data() +
                                                    sizeof(click_ether));
    ip_hdr->ip_v   = 4;
    ip_hdr->ip_hl  = 5;
    ip_hdr->ip_len = htons(pkt_len);
    ip_hdr->ip_id  = p->ip_header()->ip_id;
    ip_hdr->ip_ttl = p->ip_header()->ip_ttl;
    ip_hdr->ip_p   = IP_PROTO_UDP;
    ip_hdr->ip_src.s_addr = _udp_src_addr.addr();
    ip_hdr->ip_dst.s_addr = flow_key.daddr().addr();

    // Build the UDP header.
    click_udp *udp_hdr = reinterpret_cast<click_udp *>(udp_pkt->data() +
                                                       sizeof(click_ether) +
                                                       sizeof(click_ip));
    udp_hdr->uh_sport = flow_key.sport();
    udp_hdr->uh_dport = htons(_udp_port); 
    udp_hdr->uh_ulen  = htons(sizeof(click_udp) +
                              sizeof(dr_flow_notification_msg) +
                              sentinel_len);

    // Build the notification content.
    dr_flow_notification_msg *msg =
        reinterpret_cast<dr_flow_notification_msg *>(udp_pkt->data() +
                                                     sizeof(click_ether) +
                                                     sizeof(click_ip) +
                                                     sizeof(click_udp));
    strcpy((char *)msg->dr_sentinel, "\xBA\xAD\xFE\xED");
    msg->src_addr = flow_key.saddr().addr();
    msg->dst_addr = flow_key.daddr().addr();
    msg->src_port = flow_key.sport();
    msg->dst_port = flow_key.dport();
    msg->flow_sentinel_length = htons(sentinel_len);

    char *flow_sentinel = reinterpret_cast<char *>(
                            udp_pkt->data() + sizeof(click_ether) +
                                              sizeof(click_ip) +
                                              sizeof(click_udp) +
                                              sizeof(dr_flow_notification_msg));
    strncpy(flow_sentinel, sentinel, sentinel_len);

    // set ip/udp checksums
    ip_hdr->ip_sum = click_in_cksum((unsigned char *)ip_hdr,
                                    ip_hdr->ip_hl << 2);

    unsigned csum = click_in_cksum((unsigned char *)udp_hdr,
                                   ntohs(udp_hdr->uh_ulen));
    udp_hdr->uh_sum = click_in_cksum_pseudohdr(csum, ip_hdr,
                                               ntohs(udp_hdr->uh_ulen));

    // forward udp notification packet
    output_push_batch(2, PacketBatch::make_from_packet(udp_pkt));
}

void
SentinelDetector::incoming_udp_notification(
    const IPFlowID &flow_key, const String &sentinel)
{
    click_chatter("SentinelDetector::incoming_udp_notification: "
                  "adding previously seen flow");
    _seen_flows.set(flow_key, sentinel);
}

void
SentinelDetector::redirect_icmp_packet(
    const IPFlowID &flow_key, Packet *p, bool to_client)
{
    assert(_encoder);
    _encoder->redirect_icmp_packet(flow_key, p, to_client);
}

bool
SentinelDetector::seen_flow(const IPFlowID &flow_key, const char *buf, int len)
{
    String *flow_sentinel = _seen_flows.get_pointer(flow_key);
    if (flow_sentinel == NULL) {
        return false;
    }

    if (len < flow_sentinel->length()) {
        return false;
    }

    String sentinel(buf, flow_sentinel->length());

    return sentinel == *flow_sentinel;
}

bool
SentinelDetector::is_blacklisted(const IPAddress & decoy_host)
{
    for (Vector<DHBlacklistEntry>::iterator entry = _dh_blacklist.begin();
         entry != _dh_blacklist.end();
         ++entry) {

        if (decoy_host.matches_prefix((*entry).addr(), (*entry).mask())) {
            click_chatter("SentinelDetector::is_blacklist: "
                          "decoy address is blacklisted: %s",
                           decoy_host.unparse().c_str());
            return true;
        }
    }

    return false;
}

void
SentinelDetector::add_syn_flow(Packet *p)
{
    _cur_syn_table->add_flow(p);
}

void
SentinelDetector::remove_syn_flow(const IPFlowID &flow_key)
{
    _cur_syn_table->remove_flow(flow_key);
    _prev_syn_table->remove_flow(flow_key);
}

FlowEntry *
SentinelDetector::get_syn_flow(const IPFlowID &flow_key)
{
    FlowEntry *entry = _cur_syn_table->get_flow(flow_key);
    if (entry == NULL) {
        entry = _prev_syn_table->get_flow(flow_key);
    }
    return entry;
}

void
SentinelDetector::age_out_syn_table()
{
    click_chatter("SentinelDetector::age_out_syn_table: discarding %ld",
	    _prev_syn_table->size());

    _prev_syn_table->clear();

    FlowTable *tmp = _prev_syn_table;
    _prev_syn_table = _cur_syn_table;
    _cur_syn_table = tmp;
}

void
SentinelDetector::run_timer(Timer *timer)
{
    if (timer == &_flow_timer) {
        _flow_table.remove_inactive_flows();
        _flow_timer.reschedule_after_sec(_timeout_in_sec);

    } else if (timer == &_syn_timer) {
        age_out_syn_table();
        _syn_timer.reschedule_after_sec(_syn_table_timeout);

    } else {
        click_chatter("SentinelDetector::run_timer: unknown timer");
    }
}

enum { H_TABLE };

void
SentinelDetector::add_handlers()
{
    add_read_handler("table", read_handler, (void *)H_TABLE);
}

String
SentinelDetector::read_handler(Element *e, void *thunk)
{
    SentinelDetector *detector = (SentinelDetector *)e;

    switch ((intptr_t)thunk) {

    // return string represenation of the flow table
    case H_TABLE:
        return detector->_flow_table.table_to_str();

    default:
        return "<error>";
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(SentinelDetector)

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
#include "dr2dpencoder.hh"
#include "dr2dpprotocol.hh"
#include "sentineldetector.hh"
#include "smoosh1_hash.hh"
#include <click/args.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/vector.hh>
CLICK_DECLS


DR2DPEncoder::DR2DPEncoder()
    : _num_proxies(1),
      _ping_timer(this),
      _ping_interval(0),
      _proxy_seed(0)
{
}

DR2DPEncoder::~DR2DPEncoder()
{
}

int
DR2DPEncoder::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); i++) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0 || parts.size() > 2) {
            errh->error("conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DETECTOR", strlen("DETECTOR"))) {
            Element *e = cp_element(parts[1], this, errh);
            if (e != NULL) {
                _configured_detectors.push_back(e);
            } else {
                errh->error("invalid element");
            }

        } else if (parts[0].equals("PING", strlen("PING"))) {
            if (!IntArg().parse(parts[1], _ping_interval)) {
                errh->error("invalid ping interval");
                _ping_interval = 0;
            }

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
DR2DPEncoder::initialize(ErrorHandler *errh)
{

    FILE *fr = fopen("/dev/urandom", "r");
    if (!fr) {
	return errh->error("DR2DPEncoder::initialize: failed to create seed");
    }
    size_t rc = fread((void *) &_proxy_seed, sizeof(_proxy_seed), 1, fr);
    fclose(fr);

    if (rc != 1) {
	return errh->error("DR2DPEncoder::initialize: failed to read seed");
    }

    click_chatter("DR2DPEncoder::initialize: seed %x", _proxy_seed);

    _num_proxies = noutputs();

    if (_num_proxies < 1) {
        return errh->error("DR2DPEncoder::initialize: "
                           "invalid number of proxies %u", _num_proxies);
    }

    for (Vector<Element *>::iterator e = _configured_detectors.begin();
         e != _configured_detectors.end();
         ++e) {

        if ((*e)->cast("SentinelDetector")) {
            SentinelDetector *d = (SentinelDetector *)(*e);
            _sentinel_detectors.push_back(d);
        }
    }

    _ping_timer.initialize(this);
    if (_ping_interval > 0) {
        _ping_timer.schedule_now();
    }

    return 0;
}

void
DR2DPEncoder::cleanup(CleanupStage)
{
    _ping_timer.clear();
}

#if HAVE_BATCH
void
DR2DPEncoder::push_batch(int, PacketBatch *batch)
{
    PacketBatch * dr2dp_batch[_num_proxies];

    Packet *current = batch;

    int count = batch->count();
    int forward = 0, dropped = 0, batch_forward[_num_proxies];

    for (int i = 0; i < _num_proxies; i++) {
        dr2dp_batch[i] = NULL;
        batch_forward[i] = 0;
    }

    while (current != NULL) {
        Packet *hdr_pkt = make_header_packet(current);

        assert(current == batch);
        batch = PacketBatch::start_head(current->next());

        Packet *pkt = current;
        pkt->set_next(NULL);

        current = batch;

        if (hdr_pkt == NULL) {
            pkt->kill();
            dropped++;
            continue;
        }

        unsigned int output_port = retrieve_assigned_proxy(IPFlowID(pkt));

        if (dr2dp_batch[output_port] == NULL) {
            dr2dp_batch[output_port] = PacketBatch::make_from_packet(hdr_pkt);
        } else {
            dr2dp_batch[output_port]->append_packet(hdr_pkt);
        }

        dr2dp_batch[output_port]->append_packet(pkt);
        batch_forward[output_port]++;
        forward++;
    }

    assert(count == (forward + dropped));

    for (int i = 0; i < _num_proxies; i++) {
        if (dr2dp_batch[i] != NULL) {
            assert(dr2dp_batch[i]->count() == (2 * batch_forward[i]));
            output_push_batch(i, dr2dp_batch[i]);
        }
    }
}
#endif

void
DR2DPEncoder::push_packet(int, Packet *p)
{
    Packet *hdr_pkt = make_header_packet(p);
    if (hdr_pkt == NULL) {
        p->kill();
        return;
    }

    unsigned int output_port = retrieve_assigned_proxy(IPFlowID(p));
    output(output_port).push(hdr_pkt);
    output(output_port).push(p);
}

Packet *
DR2DPEncoder::make_header_packet(Packet *p)
{
    WritablePacket *hdr_pkt = WritablePacket::make(sizeof(dr2dp_msg));
    if (!hdr_pkt) {
        click_chatter("DR2DPEncoder::forward_packet: "
                      "failed to allocate packet");
        return NULL;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(hdr_pkt->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_FORWARD;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq(p->length());

    return hdr_pkt;
}

unsigned int
DR2DPEncoder::assign_flow_to_proxy(const IPFlowID &flow)
{
    // should really use a random seed in some way
    // maybe override the source port (i.e., 443) with seed

    struct {
	uint16_t sp, dp;
	uint32_t sa, da;
    } hash_input;

    hash_input.sp = ntohs(flow.sport());
    hash_input.dp = ntohs(flow.dport());
    hash_input.sa = flow.saddr();
    hash_input.da = flow.daddr();

    uint32_t smooshed = smoosh1_hash(
	    (const char *) &hash_input, (uint32_t) sizeof(hash_input),
	    _proxy_seed);
    unsigned mod = smooshed % 257;
    unsigned int proxy = smooshed % _num_proxies;

    // click_chatter("DR2DPEncoder::assign_flow_to_proxy: %x %x %u",
    // 	    smooshed, mod, proxy);

    return proxy;
}

unsigned int
DR2DPEncoder::retrieve_assigned_proxy(const IPFlowID &flow, bool reverse)
{
    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {

        FlowEntry *flow_entry = NULL;
        if (!reverse) {
            flow_entry = (*d)->retrieve_flow_entry(flow);
        } else {
            flow_entry = (*d)->retrieve_flow_entry(flow.reverse());
        }

        if (flow_entry != NULL) {
            return flow_entry->assigned_proxy();
        }
    }

    return 0;
}

void
DR2DPEncoder::redirect_flow(FlowEntry *entry, Packet *pkts)
{
    const String tcp_syn_options = entry->tcp_syn_options();
    const String tcp_ack_options = entry->tcp_ack_options();

    int append_len = sizeof(dr2dp_msg) +
                     sizeof(dr2dp_redirect_flow_msg) +
                     tcp_syn_options.length() +
                     tcp_ack_options.length();

    int pkt_len = 0;
    Packet *pkt = pkts;
    while (pkt != NULL) {
        pkt_len += pkt->length();
        pkt = pkt->next();
    }

    WritablePacket *p = WritablePacket::make(append_len);
    if (!p) {
        click_chatter("DR2DPEncoder::redirect_flow: "
                      "failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_REDIRECT_FLOW;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq((p->length() + pkt_len) - sizeof(dr2dp_msg));

    dr2dp_redirect_flow_msg *flow_msg =
        reinterpret_cast<dr2dp_redirect_flow_msg *>(p->data() +
                                                    sizeof(dr2dp_msg));
    flow_msg->flags = 0;
    flow_msg->syn_option_length = tcp_syn_options.length();
    flow_msg->ack_option_length = tcp_ack_options.length();

    memcpy((p->data() + (sizeof(dr2dp_msg) + sizeof(dr2dp_redirect_flow_msg))),
           tcp_syn_options.c_str(), tcp_syn_options.length());
    memcpy((p->data() + (sizeof(dr2dp_msg) +
                         sizeof(dr2dp_redirect_flow_msg) +
                         tcp_syn_options.length())),
           tcp_ack_options.c_str(), tcp_ack_options.length());

    unsigned int output_port = assign_flow_to_proxy(entry->flow_identifier());
    entry->assign_proxy(output_port);

#if HAVE_BATCH
    PacketBatch *batch = PacketBatch::make_from_packet(p);

    pkt = pkts;
    while (pkt != NULL) {
        Packet *q = pkt;
        pkt = pkt->next();

        q->set_next(NULL);
        batch->append_packet(q);
    }
    pkts = (Packet *)NULL;

    output_push_batch(output_port, batch);

#else
    output(output_port).push(p);

    pkt = pkts;
    while (pkt != NULL) {
        Packet *q = pkt;
        pkt = pkt->next();

        output(output_port).push(q);
    }
    pkts = (Packet *)NULL;
#endif
}

void
DR2DPEncoder::tls_established(const IPFlowID &flow, const String &random)
{
    assert(random.length() >= 28);

    int pkt_len = sizeof(dr2dp_msg) + sizeof(dr2dp_tls_flow_msg);

    WritablePacket *p = WritablePacket::make(pkt_len);
    if (!p) {
        click_chatter("DR2DPEncoder::tls_established: "
                      "failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_TLS_FLOW_ESTABLISHED;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq(pkt_len - sizeof(dr2dp_msg));

    dr2dp_tls_flow_msg *flow_msg = 
        reinterpret_cast<dr2dp_tls_flow_msg *>(p->data() + sizeof(dr2dp_msg));

    memset(flow_msg, 0, sizeof(dr2dp_tls_flow_msg));
    flow_msg->src_addr = flow.saddr().addr();
    flow_msg->dst_addr = flow.daddr().addr();
    flow_msg->src_port = flow.sport();
    flow_msg->dst_port = flow.dport();
    flow_msg->protocol = IP_PROTO_TCP;

    memcpy((p->data() + sizeof(dr2dp_msg) + 16), random.c_str(), 28);

    unsigned int output_port = retrieve_assigned_proxy(flow);

#if HAVE_BATCH
    PacketBatch *batch = PacketBatch::make_from_packet(p);
    output_push_batch(output_port, batch);
#else
    output(output_port).push(p);
#endif
}

void
DR2DPEncoder::redirect_icmp_packet(
    const IPFlowID &flow, Packet *pkt, bool to_client)
{
    int dr2dp_pkt_len = sizeof(dr2dp_msg) + sizeof(dr2dp_icmp_msg);

    WritablePacket *p = WritablePacket::make(dr2dp_pkt_len);
    if (!p) {
        pkt->kill();
        click_chatter("DR2DPEncoder::redirect_icmp_packet: "
                      "failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_ICMP;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq((p->length() - sizeof(dr2dp_msg)) + pkt->length());

    dr2dp_icmp_msg *icmp_msg =
        reinterpret_cast<dr2dp_icmp_msg *>(p->data() + sizeof(dr2dp_msg));

    memset(icmp_msg, 0, sizeof(dr2dp_icmp_msg));
    icmp_msg->src_addr = flow.saddr().addr();
    icmp_msg->dst_addr = flow.daddr().addr();
    icmp_msg->src_port = flow.sport();
    icmp_msg->dst_port = flow.dport();
    icmp_msg->protocol = IP_PROTO_TCP;
    if (to_client) {
        icmp_msg->flags |= DR2DP_ICMP_FLAG_TO_CLIENT;
    }

    unsigned int output_port = retrieve_assigned_proxy(flow, to_client);

#if HAVE_BATCH
    PacketBatch *batch = PacketBatch::make_from_packet(p);
    batch->append_packet(pkt);
    output_push_batch(output_port, batch);
#else
    output(output_port).push(p);
    output(output_port).push(pkt);
#endif
}

void
DR2DPEncoder::run_timer(Timer *timer)
{
    assert(timer = &_ping_timer);
    click_chatter("DR2DPEncoder::run_timer: sending ping message");

    for (int i = 0; i < _num_proxies; i++) {
        WritablePacket *p = WritablePacket::make(sizeof(dr2dp_msg));
        if (!p) {
            click_chatter("DR2DPEncoder::run_timer: "
                          "failed to allocate packet");
            continue;
        }

        dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
        msg->protocol = DR2DP_PROTOCOL_VERSION;
        msg->session_type = 0;
        msg->message_type = DR2DP_MSG_TYPE_REQUEST;
        msg->operation_type = DR2DP_OP_TYPE_PING;
        msg->response_code = 0;
        msg->xid = 0;
        msg->data_length = 0;

#if HAVE_BATCH
        PacketBatch *batch = PacketBatch::make_from_packet(p);
        output_push_batch(i, batch);
#else
        output(i).push(p);
#endif
    }

    _ping_timer.reschedule_after_sec(_ping_interval);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(DR2DPEncoder)

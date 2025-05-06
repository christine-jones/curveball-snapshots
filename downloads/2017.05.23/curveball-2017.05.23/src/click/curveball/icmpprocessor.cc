/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017 and in
 * part by a grant from the United States Department of State.
 * The opinions, findings, and conclusions stated herein are those
 * of the authors and do not necessarily reflect those of the United
 * States Department of State.
 *
 * Copyright 2011-2016 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <click/config.h>
#include "icmpprocessor.hh"
#include <click/args.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
CLICK_DECLS


ICMPProcessor::ICMPProcessor()
{
}

ICMPProcessor::~ICMPProcessor()
{
}

int
ICMPProcessor::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); ++i) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0 || parts.size() > 2) {
            errh->error("conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DETECTOR", 8)) {
            Element *e = cp_element(parts[1], this, errh);
            if (e != NULL) {
                _configured_detectors.push_back(e);
            } else {
                errh->error("invalid element");
            }

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
ICMPProcessor::initialize(ErrorHandler *)
{
    for (Vector<Element *>::iterator e = _configured_detectors.begin();
         e != _configured_detectors.end();
        ++e) {

        if ((*e)->cast("SentinelDetector")) {
            _sentinel_detectors.push_back((SentinelDetector *)(*e));
        }
    }

    return 0;
}

#if HAVE_BATCH
void
ICMPProcessor::push_batch(int, PacketBatch *batch)
{
    Packet *current = batch;
    Packet *last = batch;

    int count = batch->count();
    int forward = 0, redirect = 0;

    while (current != NULL) {
        SentinelDetector *detector = need_to_redirect_icmp_pkt(current);

        if (detector == NULL) {
            last = current;
            current = current->next();
            forward++;
            continue;
        }

        redirect++;

        if (current == batch) {
            batch = PacketBatch::start_head(current->next());
            current->set_next(NULL);

            redirect_icmp_pkt(current, detector);

            current = batch;
            last = batch;
            continue;
        }

        Packet *pkt = current;
        current = current->next();
        pkt->set_next(NULL);

        redirect_icmp_pkt(pkt, detector);

        last->set_next(current);
    }

    assert(count == (forward + redirect));

    if (batch != NULL) {
        batch->set_count(forward);
        batch->set_tail(last);
        output_push_batch(0, batch);
    }
}
#endif

void
ICMPProcessor::push_packet(int, Packet *p)
{
    SentinelDetector *detector = need_to_redirect_icmp_pkt(p);
    if (detector != NULL) {
        redirect_icmp_pkt(p, detector);
    } else {
        output(0).push(p);
    }
}

SentinelDetector *
ICMPProcessor::need_to_redirect_icmp_pkt(Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_ICMP);

    // XXX Need a plan for fragmented ICMP packets.
    if (IP_ISFRAG(p->ip_header())) {
        return NULL;
    }

    assert(p->has_transport_header());

    if ((unsigned int)p->transport_length() < sizeof(click_icmp)) {
        return NULL;
    }

    if (p->icmp_header()->icmp_type != 3  &&
        p->icmp_header()->icmp_type != 5  &&
        p->icmp_header()->icmp_type != 11 &&
        p->icmp_header()->icmp_type != 12) {
        return NULL;
    }

    const unsigned char *data = p->transport_header() + sizeof(click_icmp);
    unsigned int len = p->transport_length() - sizeof(click_icmp);

    if (len < sizeof(click_ip)) {
        //click_chatter("ICMPProcessor::need_to_redirect_icmp_pkt: "
        //              "IP header not included within packet");
        return NULL;
    }

    const click_ip *ip_hdr = reinterpret_cast<const click_ip *>(data);
    unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

    if (len < ip_hdr_len + sizeof(click_tcp)) {
        //click_chatter("ICMPProcessor::need_to_redirect_icmp_pkt: "
        //              "TCP header not included within packet");
        return NULL;
    }

    const click_tcp *tcp_hdr =
                         reinterpret_cast<const click_tcp *>(data + ip_hdr_len);

    // addrs/ports required to be in network byte order
    IPFlowID flow_id(IPAddress(ip_hdr->ip_src), tcp_hdr->th_sport,
                     IPAddress(ip_hdr->ip_dst), tcp_hdr->th_dport);

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {

        if ((*d)->redirected_flow(flow_id) ||
            (*d)->redirected_flow(flow_id.reverse())) {

            // annotate packet with flow identifier
            p->set_anno_u32(0,  flow_id.saddr().addr());
            p->set_anno_u32(4,  flow_id.daddr().addr());
            p->set_anno_u16(8,  flow_id.sport());
            p->set_anno_u16(10, flow_id.dport());

            return (*d);
        }
    }

    return NULL;
}

void
ICMPProcessor::redirect_icmp_pkt(Packet *p, SentinelDetector *detector)
{
    IPFlowID flow_id(p->anno_u32(0), p->anno_u16(8),
                     p->anno_u32(4), p->anno_u16(10));

    if (detector->redirected_flow(flow_id)) {
        detector->redirect_icmp_packet(flow_id, p);

    } else if (detector->redirected_flow(flow_id.reverse())) {
        detector->redirect_icmp_packet(flow_id, p, true);

    } else {
        click_chatter("ICMPProcessorr::redirect_icmp_pkt: "
                      "flow incorrectly identified for redirection");
        p->kill();
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ICMPProcessor)

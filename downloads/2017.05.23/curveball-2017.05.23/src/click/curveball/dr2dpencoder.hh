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

#ifndef CURVEBALL_DR2DPENCODER_HH
#define CURVEBALL_DR2DPENCODER_HH
#include <click/batchelement.hh>
#include <click/ipflowid.hh>
#include <click/timer.hh>
#include "flowtable.hh"
CLICK_DECLS

class SentinelDetector;


class DR2DPEncoder : public BatchElement { public:

    DR2DPEncoder();
    ~DR2DPEncoder();

    const char *class_name() const	{ return "DR2DPEncoder"; }
    const char *port_count() const	{ return "1/-"; }
    const char *processing() const	{ return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

#if HAVE_BATCH
    void push_batch(int port, PacketBatch *batch);
#endif
    void push_packet(int port, Packet *p);

    // Process any configured timers that have fired.
    void run_timer(Timer *timer);

    // Redirect the initial sentinel packets of a newly identified
    // Curveball flow. The 'pkts' parameter will be NULL on return.
    void redirect_flow(FlowEntry *entry, Packet *pkts);

    void tls_established(const IPFlowID &flow, const String &random);

    void redirect_icmp_packet(const IPFlowID &flow,
                              Packet *pkt,
                              bool to_client);

  private:

    unsigned int assign_flow_to_proxy(const IPFlowID &flow);
    unsigned int retrieve_assigned_proxy(const IPFlowID &flow,
                                         bool reverse = false);

    Packet * make_header_packet(Packet *p);

    unsigned int _num_proxies;

    Vector<SentinelDetector *>	_sentinel_detectors;
    Vector<Element *>		_configured_detectors;

    Timer 	_ping_timer;
    uint32_t	_ping_interval;
    uint32_t	_proxy_seed;
};

CLICK_ENDDECLS
#endif

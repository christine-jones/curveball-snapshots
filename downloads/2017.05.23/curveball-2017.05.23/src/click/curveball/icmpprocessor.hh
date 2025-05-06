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

#ifndef CURVEBALL_ICMPPROCESSOR_HH
#define CURVEBALL_ICMPPROCESSOR_HH
#include <click/batchelement.hh>
#include "sentineldetector.hh"
CLICK_DECLS

// Element that handles incoming ICMP packets.

class ICMPProcessor : public BatchElement {
  public:

    ICMPProcessor();
    ~ICMPProcessor();

    const char *class_name() const	{ return "ICMPProcessor"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

#if HAVE_BATCH
    void push_batch(int, PacketBatch *);
#endif
    void push_packet(int, Packet *);

  private:

    SentinelDetector * need_to_redirect_icmp_pkt(Packet *p);
    void redirect_icmp_pkt(Packet *p, SentinelDetector *detector);

    // reference to sentinel detector elements
    Vector<SentinelDetector *>	_sentinel_detectors;
    Vector<Element *>		_configured_detectors;
};


CLICK_ENDDECLS
#endif

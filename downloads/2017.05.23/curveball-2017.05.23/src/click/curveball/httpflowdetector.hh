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

#ifndef CURVEBALL_HTTPFLOWDETECTOR_HH
#define CURVEBALL_HTTPFLOWDETECTOR_HH
#include "sentineldetector.hh"
CLICK_DECLS

// Element that detects and redirects Curveball packets.
//
// It is assumed that incoming packets are HTTP protocol messages.
// Packets to be redirected to the Curveball system are pushed out the
// element's outbound interface 0. All other packets are pushed out
// interface 1.

class HTTPFlowDetector : public SentinelDetector {
  public:

    HTTPFlowDetector();
    ~HTTPFlowDetector();

    const char *class_name() const	{ return "HTTPFlowDetector"; }

    void * cast(const char *name);

  private:

    // Handles incoming non-SYN TCP packets.
    virtual SentinelDetector::Packet_Action process_non_syn_packet(Packet *p);

    // Inspects packet for sentinel.
    SentinelDetector::Packet_Action
        process_http_data_packet(Packet *p, FlowEntry *entry);
    SentinelDetector::Packet_Action
        process_sentinel_segment(Packet *p, FlowEntry *entry);

    void process_get_message(const IPFlowID &flow_key,
                             const String &get_msg,
                             String &sentinel);
    void process_cookie_field(const IPFlowID &flow_key,
                              const String &cookie_field,
                              String &sentinel);

    // Determines if the given buffer contains a Curveball sentinel.
    bool sentinel_packet(const IPFlowID &flow_key, const char *buf, int len);
};


CLICK_ENDDECLS
#endif

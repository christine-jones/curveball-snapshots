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

#ifndef CURVEBALL_TLSHELLOSENTINELDETECTOR_HH
#define CURVEBALL_TLSHELLOSENTINELDETECTOR_HH
#include "sentineldetector.hh"
#include "flowfilter.hh"
CLICK_DECLS

// Element that detects Curveball sentinels within packets.
//
// It is assumed that incoming packets are TLS Heloo protocol messages.
// Packets are insepcted to determine if they contain a known Curveball
// sentinel. Packets that contain a sentinel are pushed out the element's
// outbound interface 0. All other packets are pushed out interface 1.
//
// A flow key is extracted from packets containing the Curveball sentinel.
// Flow keys are passed to the configured FlowFilter element.
//
// A set of valid Curveball sentinels are maintained within a Bloom filter.
// A method interface is available for uplaoding new sentinel Bloom filters.

class TLSHelloSentinelDetector : public SentinelDetector { public:

    TLSHelloSentinelDetector();
    ~TLSHelloSentinelDetector();

    const char *class_name() const { return "TLSHelloSentinelDetector"; }

    void * cast(const char *name);

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push_packet(int port, Packet *p);

  private:

    // Returns 'true' if the packet is a TLS Hello protocol message;
    // 'false' otherwise.
    bool tls_hello_packet(Packet *p);

    // Determine if the packet contains a Curveball sentinel.
    bool redirect_packet(Packet *p);
    bool string_sentinel(Packet *p);

    // Reference of flow filter element to which to push flow key updates.
    FlowFilter *_flow_filter;

};


CLICK_ENDDECLS
#endif

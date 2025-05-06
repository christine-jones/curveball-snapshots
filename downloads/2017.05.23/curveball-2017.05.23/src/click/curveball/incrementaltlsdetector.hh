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

#ifndef CURVEBALL_INCREMENTALTLSDETECTOR_HH
#define CURVEBALL_INCREMENTALTLSDETECTOR_HH
#include <click/element.hh>
#include "flowfilter.hh"
CLICK_DECLS

// Element that detects Curveball sentinels within packets.
//
// This is an early, incremental implememntation of the TLSHelloDetector
// element. It is assumed that incoming packets are TLS Hello protocol
// messages. Packets are inspected to determine if they contain a known
// Curveball sentinel (simply a configured string). Packets that contain
// the sentinel are pushed out the element's outbound interface 0. All
// other packets are pushed out interface 1.
//
// Also, a flow key is extracted from packets containing the Curveball
// sentinel. Flow keys are passed to the configured FlowFilter element.

class IncrementalTLSDetector : public Element { public:

    IncrementalTLSDetector();
    ~IncrementalTLSDetector();

    const char *class_name() const	{ return "IncrementalTLSDetector"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int port, Packet *p);

  private:

    // Returns 'true' if packet is a TLS Hello protocol packet;
    // 'false' otherwise.
    bool tls_hello_packet(Packet *p);

    // Determine if packet contains the Curveball sentinel.
    bool redirect_packet(Packet *p);

    // Known sentinel that marks packets for Curveball redirection.
    String _sentinel;

    // Reference of flow filter element to which to push flow key updates.
    FlowFilter *_flow_filter;

};

CLICK_ENDDECLS
#endif

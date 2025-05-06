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

#ifndef CURVEBALL_INCREMENTALFILTER_HH
#define CURVEBALL_INCREMENTALFILTER_HH
#include <click/element.hh>
#include <click/string.hh>
#include "flowfilter.hh"
CLICK_DECLS

// Element that identifies Curveball flows requiring redirection.
//
// This is an early, incremental implementation of the TLSHelloFilter
// element. Packets destined to a configured port and that contain the
// sentinel string are identified as requiring redirection by Curveball
// and are pushed out the element's outbound interface 0. Packets destined
// to the Curveball port but that do not contain the Curveball sentinel
// are pushed out interface 1 for additional inspection. All other
// packets are considered to be non-Curveball, and pushed out interface 2.
//
// Also, a flow key is extracted from packets containing the Curveball
// sentinal. Flow keys are passed to the configured FlowFilter element.

class IncrementalFilter : public Element { public:

    IncrementalFilter();
    ~IncrementalFilter();

    const char *class_name() const	{ return "IncrementalFilter"; }
    const char *port_count() const	{ return "1/3"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int port, Packet *p);

  private:

    // Returns 'true' if packet is a non-first fragment; 'false' otherwise.
    bool non_first_fragment(Packet *p);

    // Returns 'true' if packet is destined to the configured Curveball
    // port; 'false' otherwise.
    bool match_port(Packet *p);

    // Returns 'true' if packet contains the configured Curveball sentinel;
    // 'false' otherwise.
    bool detect_sentinel(Packet *p);

    // Curveball destination port.
    uint16_t _port;

    // Known sentinel that marks packets for Curveball redirection.
    String   _sentinel;

    // Reference of flow filter element to which to push flow key updates.
    FlowFilter *_flow_filter;

};

CLICK_ENDDECLS
#endif

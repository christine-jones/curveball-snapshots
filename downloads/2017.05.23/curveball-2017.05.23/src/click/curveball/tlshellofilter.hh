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

#ifndef CURVEBALL_TLSHELLOFILTER_HH
#define CURVEBALL_TLSHELLOFILTER_HH
#include <click/element.hh>
CLICK_DECLS

// Element that classifies packets as possible Curveball sentinel packets,
// possible Curveball non-sentinel packets, or non-Curveball packets.
//
// TLS Hello packets are pushed out the element's outbound interface 0.
// Such packets need to be inspected for a Curveball sentinel. All other
// TLS packets are pushed out interface 1. Such packets may match an
// already marked Curveball flow. Non-TLS packets are considered to be
// non-Curveball, and pushed out interface 2.

class TLSHelloFilter : public Element { public:

    TLSHelloFilter();
    ~TLSHelloFilter();

    const char *class_name() const	{ return "TLSHelloFilter"; }
    const char *port_count() const	{ return "1/3"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    void push(int port, Packet *p);

  private:

    // Returns 'true' if packet is a non-first fragment; 'false' otherwise.
    bool non_first_fragment(Packet *p);

    // Returns 'true' if packet is a TLS protocol packet; 'false' otherwise.
    bool tls_protocol(Packet *p);

    // Returns 'true' if packet is a TLS Hello protocol packet;
    // 'false' otherwise.
    bool tls_hello(Packet *p);

};

CLICK_ENDDECLS
#endif

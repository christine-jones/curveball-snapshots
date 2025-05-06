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

#ifndef CURVEBALL_REMOVEFILTER_HH
#define CURVEBALL_REMOVEFILTER_HH
#include <click/element.hh>
#include "flowfilter.hh"
CLICK_DECLS

// Element used for unit testing the FlowFilter element.
//
// A flow key is extracted for each received packet and passed to the
// registered FlowFilter element for removal. Packets are then dropped.
//
// See test/flowfilter.testie.

class RemoveFilter : public Element { public:

    RemoveFilter();
    ~RemoveFilter();

    const char *class_name() const	{ return "RemoveFilter"; }
    const char *port_count() const	{ return "1/0"; }
    const char *processing() const	{ return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int port, Packet *p);

  private:

    FlowFilter *_flow_filter;

};

CLICK_ENDDECLS
#endif

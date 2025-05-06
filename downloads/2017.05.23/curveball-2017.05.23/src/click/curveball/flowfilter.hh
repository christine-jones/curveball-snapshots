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

#ifndef CURVEBALL_FLOWFILTER_HH
#define CURVEBALL_FLOWFILTER_HH
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/hashtable.hh>
#include <click/timer.hh>
CLICK_DECLS

// Element that tracks Curveball flows that are being actively redirected
// to the decoy proxy.
//
// A flow key is extracted for each incoming packet. If the flow key is
// contained within the flow table (implemented as a hash table), the
// packet is identified as requiring redirection to the Curveball decoy
// proxy and is pushed out the element's outbound interface 0. Packets
// not identified as Curveball are pushed out interface 1.
//
// A method interface is provided that allows other elements to add flow
// keys to the flow table that identifies active Curveball flows. A timer
// is used to remove flows from the flow table that have been inactive for
// a configured period of time.

class FlowFilter : public Element { public:

    FlowFilter();
    ~FlowFilter();

    const char *class_name() const	{ return "FlowFilter"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    void push(int port, Packet *p);

    // Installs the element's handlers.
    void add_handlers();

    // Processes any configured timers that have fired.
    void run_timer(Timer *timer);

    // Adds a flow key to the flow table.
    void add_flow(const IPFlowID &flow_key);

    // Removes a flow key from the flow table.
    void remove_flow(const IPFlowID &flow_key);

    // Returns a string representation of the flow table; used for test/debug.
    String table() const;

  private:

    // Determine if packet with given flow key requires Curveball redirection.
    bool redirect_flow(const IPFlowID &flow_key);

    // Callback used to process read handlers.
    static String read_handler(Element *, void *);

    // Table of flow keys that represent flows requiring Curveball redirection.
    HashTable<IPFlowID, int>	_flow_table;

    // Time interval to identify inactive Curveball flows.
    uint32_t			_timeout_in_sec;

    // Timer used to periodically inspect flow table for inactive flows.
    Timer			_flow_timer;

};

CLICK_ENDDECLS
#endif

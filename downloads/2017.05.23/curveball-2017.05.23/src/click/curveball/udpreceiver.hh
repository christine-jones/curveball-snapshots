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

#ifndef CURVEBALL_UDPRECEIVER_HH
#define CURVEBALL_UDPRECEIVER_HH
#include <click/batchelement.hh>
#include "sentineldetector.hh"
CLICK_DECLS

// Element that handles incoming Curveball UDP flow notification packets.

class UDPReceiver : public BatchElement {
  public:

    UDPReceiver();
    ~UDPReceiver();

    const char *class_name() const	{ return "UDPReceiver"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

#if HAVE_BATCH
    void push_batch(int port, PacketBatch *batch);
#endif
    void push_packet(int port, Packet *p);

  private:

    bool forward_incoming_pkt(Packet *p);
    bool process_notification_pkt(Packet *p);

    // destination port of inspected traffic
    uint16_t 	_port;

    // local IP address of router
    IPAddress	_local_addr;

    // reference to sentinel detector elements needing to be notified
    Vector<SentinelDetector *>	_sentinel_detectors;
    Vector<Element *>		_configured_detectors;
};


CLICK_ENDDECLS
#endif

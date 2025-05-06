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

#ifndef CURVEBALL_PACKETSPLITTER_HH
#define CURVEBALL_PACKETSPLITTER_HH
#include <click/element.hh>
CLICK_DECLS

// Element that splits non-SYN TCP packets.
//

class PacketSplitter : public Element { public:

    PacketSplitter();
    ~PacketSplitter();

    const char *class_name() const	{ return "PacketSplitter"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *p);

  private:

    bool syn_packet(Packet *p);
    bool ack_packet(Packet *p);
    void split_packet(Packet *p);

    // Destination port of inspected traffic.
    uint16_t 	_port;

    // Number of bytes included in each tcp packet segment.
    int		_segment_size;

};


CLICK_ENDDECLS
#endif

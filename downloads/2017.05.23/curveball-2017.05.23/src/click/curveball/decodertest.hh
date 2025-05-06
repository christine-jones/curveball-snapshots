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

#ifndef CURVEBALL_DECODERTEST_HH
#define CURVEBALL_DECODERTEST_HH
#include <click/element.hh>
CLICK_DECLS


// Element that processes incoming DR2DP protocol messages (contained
// within Click packets) from the decoy proxy.
class DecoderTest : public Element { public:

    DecoderTest();
    ~DecoderTest();

    const char *class_name() const	{ return "DecoderTest"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    void push(int port, Packet *p);

  private:

    void parse(Packet *p);

    // Methods used to process DR2DP messages that span multiple packet buffers.
    void	new_pkt_buffer(Packet *p, uint64_t length_needed = 0);
    Packet *	append_to_pkt_buffer(Packet *p);
    void	process_pkt_buffer();
    void	release_pkt_buffer();
    void	add_pkt(Packet *p);

    // State to handle DR2DP messages that span multiple packet buffers.
    Packet *	_pktbuf;
    bool	_header_needed;
    uint64_t    _bytes_remaining;

};

CLICK_ENDDECLS
#endif

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

#ifndef CURVEBALL_DR2DPDECODER_HH
#define CURVEBALL_DR2DPDECODER_HH
#include <click/element.hh>
#include <click/string.hh>
#include "sentineldetector.hh"
CLICK_DECLS


// Element that processes incoming DR2DP protocol messages (contained
// within Click packets) from the decoy proxy.
class DR2DPDecoder : public Element { public:

    DR2DPDecoder();
    ~DR2DPDecoder();

    const char *class_name() const	{ return "DR2DPDecoder"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }
    int        configure_phase() const	{ return CONFIGURE_PHASE_INFO; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int port, Packet *p);

  private:

    void parse(Packet *p);
    void parse_filter_msg(Packet *p);
    void parse_remove_flow_msg(Packet *p);
    void parse_dh_blacklist_msg(Packet *);

    void forward_packet(Packet *p);
    bool retrieve_flow_entry(Packet *p, FlowEntry **entry);

    // methods to process DR2DP messages that span multiple packet buffers
    void	new_pkt_buffer(Packet *p, uint64_t length_needed = 0);
    Packet *	append_to_pkt_buffer(Packet *p);
    void	process_pkt_buffer();
    void	release_pkt_buffer();
    void	add_pkt(Packet *p);

    #define NEXT_PKT_INDEX 0
    #define PREV_PKT_INDEX 8
    Packet *	next_pkt(Packet *p) const;
    Packet *	prev_pkt(Packet *p) const;
    void	set_next_pkt(Packet *p, Packet *next);
    void	set_prev_pkt(Packet *p, Packet *prev);

    // state to handle DR2DP messages that span multiple packet buffers
    Packet *	_pktbuf;
    bool	_header_needed;
    uint64_t    _bytes_remaining;

    // valid Curveball sentinels
    BloomFilter	_sentinels;

    // decoy host blacklist
    Vector<DHBlacklistEntry> _dh_blacklist;

    // reference of sentinel detector element to which to push state updates
    // received from the decoy proxy
    Vector<SentinelDetector *>	_sentinel_detectors;
    Vector<Element *>		_configured_detectors;

    // name of file from which to upload new sentinel bloom filters
    String _filter_file;

    // name of file from which to upload a new DH blacklist
    String _dh_blacklist_file;

};

CLICK_ENDDECLS
#endif

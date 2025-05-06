/*
 * This material is funded in part by a grant from the United States
 * Department of State. The opinions, findings, and conclusions stated
 * herein are those of the authors and do not necessarily reflect
 * those of the United States Department of State.
 *
 * Copyright 2016 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef CURVEBALL_CBPACKETSTATS_HH
#define CURVEBALL_CBPACKETSTATS_HH
#include <click/batchelement.hh>
#include <click/timer.hh>
CLICK_DECLS

class CBPacketStats : public BatchElement {

  public:

    CBPacketStats();
    ~CBPacketStats();

    const char *class_name() const	{ return "CBPacketStats"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    void smaction(Packet *);
#if HAVE_BATCH
    PacketBatch * simple_action_batch(PacketBatch *);
#endif
    Packet * simple_action(Packet *);

    void run_timer(Timer *timer);

  private:

    void print_stats();
    void clear_stats();

#ifdef HAVE_INT64_TYPES
    uint64_t	_packet_count;
    uint64_t	_byte_count;
#else
    uint32_t	_packet_count;
    uint32_t	_byte_count;
#endif

    bool 	_tcp;
#ifdef HAVE_INT64_TYPES
    uint64_t	_flow_count;
#else
    uint32_t	_flow_count;
#endif

    String	_label;
    uint32_t	_interval_in_sec;

    Timer	_print_stats_timer;

    // _zero_count counts the number of consecutive observations in
    // print_stats() that have a zero packet count.  If this reaches
    // _zero_max, then the system may assume that the netmap driver
    // (or the network itself) has failed and it should halt.  See
    // print_stats() for more info.
    //
    uint32_t	_zero_count;
    uint32_t	_zero_max;

};

CLICK_ENDDECLS
#endif

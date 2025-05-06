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

#ifndef CURVEBALL_CBUNSTRIPETHER_HH
#define CURVEBALL_CBUNSTRIPETHER_HH
#include <click/batchelement.hh>
CLICK_DECLS

class CBUnstripEther : public BatchElement {

  public:

    CBUnstripEther()  {}
    ~CBUnstripEther() {}

    const char *class_name() const	{ return "CBUnstripEther"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    void unstrip_packet(Packet *p);

#if HAVE_BATCH
    void push_batch(int port, PacketBatch *batch);
#endif
    void push_packet(int port, Packet *p);

};

CLICK_ENDDECLS
#endif

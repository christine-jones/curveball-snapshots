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

#include <click/config.h>
#include "cbunstripether.hh"
#include <clicknet/ether.h>
CLICK_DECLS

void
CBUnstripEther::unstrip_packet(Packet *p)
{
    assert(p->has_mac_header());
    assert(p->headroom() >= p->mac_header_length());

    p->push(p->mac_header_length());
}

#if HAVE_BATCH
void
CBUnstripEther::push_batch(int port, PacketBatch *batch)
{
    Packet *p = batch;
    while (p != NULL) {
        unstrip_packet(p);
        p = p->next();
    }

    output_push_batch(0, batch);
}
#endif

void
CBUnstripEther::push_packet(int port, Packet *p)
{
    unstrip_packet(p);
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CBUnstripEther)

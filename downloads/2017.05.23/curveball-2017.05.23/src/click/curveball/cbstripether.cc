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
#include "cbstripether.hh"
#include <clicknet/ether.h>
CLICK_DECLS

void
CBStripEther::strip_packet(Packet *p)
{
    assert(p->length() >= sizeof(click_ether));
    const click_ether *ether_hdr = (const click_ether *)(p->data());

    int bytes_to_strip = sizeof(click_ether);
    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_8021Q) {
        bytes_to_strip = sizeof(click_ether_vlan);
    }

    p->set_mac_header(p->data(), bytes_to_strip);
    p->pull(bytes_to_strip);
}

#if HAVE_BATCH
void
CBStripEther::push_batch(int port, PacketBatch *batch)
{
    Packet *p = batch;
    while (p != NULL) {
        strip_packet(p);
        p = p->next();
    }

    output_push_batch(0, batch);
}
#endif

void
CBStripEther::push_packet(int port, Packet *p)
{
    strip_packet(p);
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CBStripEther)

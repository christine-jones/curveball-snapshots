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
#include "cbpacketstats.hh"
#include <click/straccum.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS

CBPacketStats::CBPacketStats():
    _packet_count(0), _byte_count(0), _tcp(false), _flow_count(0),
    _interval_in_sec(0), _print_stats_timer(this),
    _zero_count(0), _zero_max(0)
{
}

CBPacketStats::~CBPacketStats()
{
}

int
CBPacketStats::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // default to print stats every second
    _interval_in_sec = 1;

    return cp_va_kparse(conf, this, errh,
                        "LABEL", 0, cpString, &_label,
                        "INTERVAL", 0, cpUnsigned, &_interval_in_sec,
                        "TCP", 0, cpBool, &_tcp,
                        "MAX_ZERO_INTERVAL", 0, cpUnsigned, &_zero_max,
                        cpEnd);
}

int
CBPacketStats::initialize(ErrorHandler *errh)
{
    if (_interval_in_sec > 0) {
        _print_stats_timer.initialize(this);
        _print_stats_timer.schedule_after_sec(_interval_in_sec);
    }

    return 0;
}

void
CBPacketStats::cleanup(CleanupStage)
{
    if (_interval_in_sec > 0) {
        _print_stats_timer.clear();
    }
}

void
CBPacketStats::run_timer(Timer *timer)
{
    assert(timer == &_print_stats_timer);

    print_stats();
    clear_stats();

    _print_stats_timer.reschedule_after_sec(_interval_in_sec); 
}

void
CBPacketStats::smaction(Packet *p)
{
    _packet_count++;
    _byte_count += p->length();

    if (_tcp) {
        assert(p->has_network_header());
        assert(p->ip_header()->ip_p == IP_PROTO_TCP);
        assert(p->has_transport_header());

        if ((p->tcp_header()->th_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
            _flow_count++;
        }
    }
}

#if HAVE_BATCH
PacketBatch *
CBPacketStats::simple_action_batch(PacketBatch *batch)
{
    FOR_EACH_PACKET(batch, p) {
        smaction(p);
    }
    return batch;
}
#endif

Packet *
CBPacketStats::simple_action(Packet *p)
{
    smaction(p);
    return p;
}

void
CBPacketStats::print_stats()
{
    StringAccum stats;

    // Simple deadman switch, checked only for the "Incoming" stats:
    // if we haven't seen any packets in a while, then assume
    // something has gone wrong and halt (and dump core)
    //
    // TODO: remove or set _zero_max to 0 when no longer needed.
    //
    if (_label == "Incoming") {
	if (_packet_count == 0) {
	    _zero_count++;
	}
	else {
	    _zero_count = 0;
	}

	if ((_zero_max > 0) && (_zero_max <= _zero_count)) {
	    click_chatter("no packets seen in %u checks: exiting", _zero_max);
	    // try a SEGV, to get a core.  If that doesn't work,
	    // then resort to an ordinary KILL
	    //
	    raise(SIGSEGV);
	    raise(SIGKILL);
	}
    }

    stats << Timestamp::now().unparse() << " ";

    if (_label.length() > 0) {
        stats << _label << " ";
    }

    stats << "packets " << _packet_count;
    stats << " ";
    stats << "bytes " << _byte_count;

    if (_tcp) {
        stats << " ";
        stats << "new_flows " << _flow_count;
    }
    stats << " ";
    stats << "MB " << _byte_count / 1000000;

    click_chatter("%s", stats.c_str());
}

void
CBPacketStats::clear_stats()
{
    _packet_count = 0;
    _byte_count = 0;
    _flow_count = 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CBPacketStats)

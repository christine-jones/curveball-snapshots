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

#include <click/config.h>
#include "flowfilter.hh"
#include <click/confparse.hh>
#include <click/glue.hh>
#include <click/vector.hh>
CLICK_DECLS


FlowFilter::FlowFilter()
    : _flow_table(0), _timeout_in_sec(0), _flow_timer(this)
{
}

FlowFilter::~FlowFilter()
{
}

int
FlowFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    //TODO: What do we really want the default timeout to be?
    //      A timeout of 7 days has been added to the router config file.
    _timeout_in_sec = 60 * 60 * 24 * 7; // 7 day default (for demoing)

    return cp_va_kparse(conf, this, errh,
                        "TIMEOUT", 0, cpUnsigned, &_timeout_in_sec,
                        cpEnd);
}

int
FlowFilter::initialize(ErrorHandler *)
{
    _flow_timer.initialize(this);
    _flow_timer.schedule_after_sec(_timeout_in_sec);

    return 0;
}

void
FlowFilter::cleanup(CleanupStage)
{
    _flow_table.clear();
    _flow_timer.clear();
}

void
FlowFilter::push(int, Packet *p)
{
    // Curveball flow to be redirected to the decoy proxy.
    if (redirect_flow(IPFlowID(p))) {
        output(0).push(p);

    // Non-Curveball flow to be forwarded as normal.
    } else {
        output(1).push(p);
    }
}

void
FlowFilter::run_timer(Timer *timer)
{
    assert(timer == &_flow_timer);

    Vector<IPFlowID> inactive_flows;

    // Identify inactive flows.
    // Inactive flows cannot be removed during this iteration of the flow
    // table because the iterator would become invalid.
    for(HashTable<IPFlowID, int>::iterator flow = _flow_table.begin();
        flow != _flow_table.end();
        ++flow) {

        // Active flows have been marked with a '1'.
        if (_flow_table[flow.key()] == 0) {
            inactive_flows.push_back(flow.key());
        }

        // Reset all flows as inactive for the next time interval.
        // A flow is marked again as active if a packet is received on
        // that flow in the next time interval.
        _flow_table[flow.key()] = 0;
    }

    // Remove all inactive flows from the flow table.
    for (Vector<IPFlowID>::iterator flow = inactive_flows.begin();
         flow != inactive_flows.end();
         ++flow) {

        remove_flow(*flow);
    }

    click_chatter("FlowFilter::run_timer: "
                  "removed inactive flows; rescheduling timer");
    _flow_timer.reschedule_after_sec(_timeout_in_sec);
}

void
FlowFilter::add_flow(const IPFlowID &flow_key)
{
    // Insert the flow with a '1' to indicate that the flow is active.
    if (!_flow_table.find_insert(flow_key, 1)) {
        click_chatter("FlowFilter::add_flow: failed to insert flow %s",
                      flow_key.unparse().c_str());
        return;
    }

    click_chatter("FlowFilter::add_flow: inserted flow %s",
                  flow_key.unparse().c_str());
}

void
FlowFilter::remove_flow(const IPFlowID &flow_key)
{
    _flow_table.erase(flow_key);
    click_chatter("FlowFilter::remove_flow: removed flow %s",
                  flow_key.unparse().c_str());
}

bool
FlowFilter::redirect_flow(const IPFlowID &flow_key)
{
    if (_flow_table.find(flow_key) == _flow_table.end()) {
        // Flow key not found in flow table; packet is non-Curveball.
        return false;
    }

    // Mark flow as active.
    _flow_table[flow_key] = 1;

    return true;
}

String
FlowFilter::table() const
{
    String table;

    table  = "---------- FlowFilter ----------\n";
    for(HashTable<IPFlowID, int>::const_iterator flow = _flow_table.begin();
        flow != _flow_table.end();
        ++flow) {
        table += flow.key().unparse();
        table += '\n';
    }
    table += "--------------------------------\n";

    return table;
}

enum { H_TABLE };

void
FlowFilter::add_handlers()
{
    add_read_handler("table", read_handler, (void *)H_TABLE);
}

String
FlowFilter::read_handler(Element *e, void *thunk)
{
    FlowFilter *filter = (FlowFilter *)e;

    switch ((intptr_t)thunk) {

    // return string represenation of the flow table
    case H_TABLE:
        return filter->table();

    default:
        return "<error>";
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(FlowFilter)

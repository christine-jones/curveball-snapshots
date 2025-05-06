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
#include "removefilter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/ipflowid.hh>
CLICK_DECLS


RemoveFilter::RemoveFilter()
    : _flow_filter((FlowFilter *)NULL)
{
}

RemoveFilter::~RemoveFilter()
{
}

int
RemoveFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "FLOW", cpkP+cpkM, cpElement, &_flow_filter,
                        cpEnd);
}

int
RemoveFilter::initialize(ErrorHandler *errh)
{
    if (!_flow_filter || !_flow_filter->cast("FlowFilter")) {
        errh->warning("%s: FlowFilter element is missing or has the wrong type",
                      name().c_str());
        _flow_filter = (FlowFilter *)NULL;
    }

    return 0;
}

void
RemoveFilter::push(int, Packet *p)
{
    // Extract packet flow key and pass to the registered FlowFilter element.
    if (_flow_filter != NULL) {
        _flow_filter->remove_flow(IPFlowID(p));
    }

    // No need for packet any longer; release memory.
    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(RemoveFilter)

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
#include "incrementalfilter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


IncrementalFilter::IncrementalFilter()
    : _port(0), _flow_filter((FlowFilter *)NULL)
{
}

IncrementalFilter::~IncrementalFilter()
{
}

int
IncrementalFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "PORT", cpkP+cpkM, cpTCPPort, &_port,
                        "SENTINEL", cpkP+cpkM, cpString, &_sentinel,
                        "FLOW", cpkP+cpkM, cpElement, &_flow_filter,
                        cpEnd);
}

int
IncrementalFilter::initialize(ErrorHandler *errh)
{
    if (!_flow_filter || !_flow_filter->cast("FlowFilter")) {
        errh->warning("%s: FlowFilter element is missing or has the wrong type",
                      name().c_str());
        _flow_filter = (FlowFilter *)NULL;
    }

    return 0;
}

void
IncrementalFilter::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are non-Curveball.
    if (non_first_fragment(p)) {
        output(2).push(p);
        return;
    }

    assert(p->has_transport_header());

    // Packet destined to Curveball port and contains Curveball sentinel.
    if (match_port(p) && detect_sentinel(p)) {

        // Update configured flow filter element with extracted flow key.
        if (_flow_filter != NULL) {
            _flow_filter->add_flow(IPFlowID(p));
        }
	
        output(0).push(p);

    // Packet destined to Curveball port but does not contain sentinel.
    } else  if (match_port(p)) {
        output(1).push(p);

    // Non-Curveball packet.
    } else {
        output(2).push(p);
    }
}

bool
IncrementalFilter::non_first_fragment(Packet *p)
{
    return (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header()));
}

bool
IncrementalFilter::match_port(Packet *p)
{
    return (ntohs(p->tcp_header()->th_dport) == _port);
}

bool
IncrementalFilter::detect_sentinel(Packet *p)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    return ((nbytes >= _sentinel.length()) &&
            (_sentinel == String((const char *)data, _sentinel.length())));
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IncrementalFilter)

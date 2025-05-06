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

#ifndef CURVEBALL_FRAGIDENTIFIER_HH
#define CURVEBALL_FRAGIDENTIFIER_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/ipflowid.hh>
CLICK_DECLS


class FragFlowEntry {
  public:

    FragFlowEntry(): _sentinel_pkt_seen(false), _num_pkts_seen(0) {}
    ~FragFlowEntry() {}

    bool 	 sentinel_pkt_seen() 	const { return _sentinel_pkt_seen; }
    unsigned int num_pkts_seen() 	const { return _num_pkts_seen; }

    void set_sentinel_pkt_seen() { _sentinel_pkt_seen = true; }
    void pkt_seen() { _num_pkts_seen++; }

  private:

    bool 	 _sentinel_pkt_seen;
    unsigned int _num_pkts_seen;

};

class FragFlowTable {
  public:

    FragFlowTable(): _flow_table(FragFlowEntry()) {}
    ~FragFlowTable() { clear(); }

    void add_flow(const IPFlowID &flow_key);
    void remove_flow(const IPFlowID &flow_key);

    FragFlowEntry * get_flow(const IPFlowID &flow_key)
                        { return _flow_table.get_pointer(flow_key); }

    void clear() { _flow_table.clear(); }

  private:

    HashTable<IPFlowID, FragFlowEntry> _flow_table;
};


// Element that identifies packets to send to the IPFragmenter.
// Used for experimental and test purposes.
//

class FragIdentifier : public Element { public:

    FragIdentifier();
    ~FragIdentifier();

    const char *class_name() const	{ return "FragIdentifier"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int, Packet *);

  private:

    void process_packet(Packet *, bool);

    bool syn_packet(Packet *);
    bool tls_sentinel_packet(Packet *);
    bool http_sentinel_packet(Packet *);

    bool         _frag_sentinel;
    bool	 _frag_all;
    unsigned int _pkt_offset;

    FragFlowTable _flow_table;

};


CLICK_ENDDECLS
#endif

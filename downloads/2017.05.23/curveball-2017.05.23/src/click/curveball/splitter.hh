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

#ifndef CURVEBALL_SPLITTER_HH
#define CURVEBALL_SPLITTER_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/ipflowid.hh>
CLICK_DECLS


class SplitterEntry {
  public:

    SplitterEntry(): _sentinel_pkt_seen(false) {}
    ~SplitterEntry() {}

    bool         sentinel_pkt_seen()    const { return _sentinel_pkt_seen; }

    void set_sentinel_pkt_seen() { _sentinel_pkt_seen = true; }

  private:

    bool         _sentinel_pkt_seen;
};

class SplitterTable {
  public:

    SplitterTable(): _flow_table(SplitterEntry()) {}
    ~SplitterTable() { clear(); }

    void add_flow(const IPFlowID &flow_key);
    void remove_flow(const IPFlowID &flow_key);

    SplitterEntry * get_flow(const IPFlowID &flow_key)
                        { return _flow_table.get_pointer(flow_key); }

    void clear() { _flow_table.clear(); }

  private:

    HashTable<IPFlowID, SplitterEntry> _flow_table;
};


// Element that splits Curveball sentinel packets.
//

class Splitter : public Element { public:

    Splitter();
    ~Splitter();

    const char *class_name() const	{ return "Splitter"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int, Packet *);

  private:

    void process_packet(Packet *, bool);

    bool syn_packet(Packet *);
    bool tls_sentinel_packet(Packet *);
    bool http_sentinel_packet(Packet *);

    void split_packet(Packet *);

    // number of bytes included in each tcp packet segment
    int		_segment_size;

    bool	_segment_all;
    bool	_reverse;
    bool	_mix_it_up;

    SplitterTable _flow_table;
};


CLICK_ENDDECLS
#endif

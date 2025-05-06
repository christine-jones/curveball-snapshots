/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017 and in
 * part by a grant from the United States Department of State.
 * The opinions, findings, and conclusions stated herein are those
 * of the authors and do not necessarily reflect those of the United
 * States Department of State.
 *
 * Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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

#ifndef CURVEBALL_FLOWTABLE_HH
#define CURVEBALL_FLOWTABLE_HH
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
#include <click/ipflowid.hh>
CLICK_DECLS

#define FLOW_STATE_ACK		1
#define FLOW_STATE_SENTINEL	2
#define FLOW_STATE_SEGMENT	3
#define FLOW_STATE_REDIRECT	4
#define FLOW_STATE_IGNORED	5

// Defines a single entry within the flow table.
class FlowEntry {
  public:

    FlowEntry()
	: _state(0), _isn(0), _assigned_proxy(0), _vlan(false), _vlan_tag(0),
          _server_tcp_ack(false), _server_proto_ack(false),
          _active(false), _pktbuf((Packet *)NULL), _seq_ptr(0),
          _maintain_buffer(false) {}
    FlowEntry(uint32_t isn, const IPFlowID &flow_identifier)
        : _state(FLOW_STATE_ACK), _isn(isn), _flow_identifier(flow_identifier),
          _assigned_proxy(0), _vlan(false), _vlan_tag(0),
          _server_tcp_ack(false), _server_proto_ack(false),
          _active(true), _pktbuf((Packet *)NULL), _seq_ptr(isn),
          _maintain_buffer(false) {}
    ~FlowEntry() { release_pkt_buffer(); }

    void set_state(int state)	{ _state = state; }
    void set_active()		{ _active = true; }
    void set_inactive()		{ _active = false; }
    void set_server_ack()	{ _server_tcp_ack = true; }
    void set_proto_ack()	{ _server_proto_ack = true; }
    void set_tcp_syn_options(const String & options)
				{ _tcp_syn_options = options; }
    void set_tcp_ack_options(const String & options)
				{ _tcp_ack_options = options; }
    void maintain_segment_buffer() { _maintain_buffer = true; }

    int		state() const		{ return _state; }
    uint32_t 	isn() const 		{ return _isn; }
    const IPFlowID & flow_identifier() const { return _flow_identifier; }
    bool 	active() const 		{ return _active; }
    bool        server_ack() const	{ return _server_tcp_ack; }
    bool	proto_ack() const	{ return _server_proto_ack; }
    Packet *	pktbuf()		{ return _pktbuf; }
    const String & tcp_syn_options() const { return _tcp_syn_options; }
    const String & tcp_ack_options() const { return _tcp_ack_options; }
    const String & segment_buffer()  const { return _segment_buffer; }

    void assign_proxy(unsigned int proxy) { _assigned_proxy = proxy; }
    unsigned int assigned_proxy() const	{ return _assigned_proxy; }

    void set_ethernet_addrs(const EtherAddress & src, const EtherAddress & dst)
	{ _ether_src = src; _ether_dst = dst; }
    const EtherAddress & get_src_ethernet() const { return _ether_src; }
    const EtherAddress & get_dst_ethernet() const { return _ether_dst; }

    void set_vlan_tag(uint16_t tag)	{ _vlan = true; _vlan_tag = tag; }
    bool 	vlan() const		{ return _vlan; }
    uint16_t	vlan_tag() const	{ return _vlan_tag; }

    // methods to process buffer of segmented sentinel packets
    bool add_pkt(Packet *p);
    bool ready_for_sentinel_check(int len);
    bool ready_for_sentinel_check(const String &end_str);
    void construct_sentinel_buf(char *buf, int len, int offset);
    void release_pkt_buffer();

  private:

    int		_state;

    // initial sequence number contained within TCP SYN packet
    uint32_t	_isn;

    IPFlowID	_flow_identifier;

    unsigned int _assigned_proxy;

    // src/dst ethernet addresses for flow
    EtherAddress _ether_src;
    EtherAddress _ether_dst;

    // record ethernet vlan tag if one included with flow
    bool	_vlan;
    uint16_t	_vlan_tag;

    // indicates whether or not server-side acks have been observed
    bool 	_server_tcp_ack;
    bool	_server_proto_ack;

    // options contained within TCP SYN/ACK packets
    String	_tcp_syn_options;
    String	_tcp_ack_options;

    // indicates that the flow has been active
    bool	_active;

    // buffer of segmented sentinel packets
    Packet *	_pktbuf;
    uint32_t    _seq_ptr;

    bool	_maintain_buffer;
    String	_segment_buffer;
    void build_segment_buffer();
};


// Class that implements a flow table that manages Curveball flows.
class FlowTable {
  public:

    FlowTable();
    ~FlowTable();

    void add_flow(Packet *p);
    void add_entry(const IPFlowID &flow_key, FlowEntry *entry);
    void remove_flow(const IPFlowID &flow_key);

    FlowEntry * get_flow(const IPFlowID &flow_key)
                    { return _flow_table.get_pointer(flow_key); }

    bool member_flow(const IPFlowID &flow_key)
             { return (_flow_table.find(flow_key) != _flow_table.end()); }

    void remove_inactive_flows();

    void clear() { _flow_table.clear(); }
    ssize_t size() { return _flow_table.size(); }

    String table_to_str() const;

  private:

    HashTable<IPFlowID, FlowEntry> _flow_table;
    void expunge_flow(const IPFlowID &flow_key);
};

CLICK_ENDDECLS
#endif

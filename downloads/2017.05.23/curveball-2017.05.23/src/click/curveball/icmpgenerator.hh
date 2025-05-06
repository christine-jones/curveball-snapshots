/* $Id$
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 * Copyright 2011 - Raytheon BBN Technologies - All Rights Reserved
 */

#ifndef CURVEBALL_ICMPGENERATOR_HH
#define CURVEBALL_ICMPGENERATOR_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/ipflowid.hh>
CLICK_DECLS


class ICMPFlowEntry {
  public:

    ICMPFlowEntry():
        _sentinel_pkt_seen(false),
        _num_pkts_seen(0), _num_reverse_pkts_seen(0),
        _num_generated(0), _pause_interval(0),
        _gen_count(0), _pause_count(0) {}
    ICMPFlowEntry(unsigned int num_generated, unsigned int pause_interval):
        _sentinel_pkt_seen(false),
        _num_pkts_seen(0), _num_reverse_pkts_seen(0),
        _num_generated(num_generated), _pause_interval(pause_interval),
        _gen_count(num_generated), _pause_count(pause_interval) {}
    ~ICMPFlowEntry() {}

    bool         sentinel_pkt_seen()	const { return _sentinel_pkt_seen; }
    unsigned int num_pkts_seen(bool reverse = false) const {
                     if (!reverse) {
                         return _num_pkts_seen;
                     } else {
                         return _num_reverse_pkts_seen;
                     }
    }

    void set_sentinel_pkt_seen() { _sentinel_pkt_seen = true; }
    void pkt_seen(bool reverse = false) {
             if (!reverse) {
                 _num_pkts_seen++;
             } else {
                 _num_reverse_pkts_seen++;
             }
    }

    bool generate_icmp();

  private:

    bool         _sentinel_pkt_seen;
    unsigned int _num_pkts_seen;
    unsigned int _num_reverse_pkts_seen;

    unsigned int _num_generated;
    unsigned int _pause_interval;

    unsigned int _gen_count;
    unsigned int _pause_count;

};

class ICMPFlowTable {
  public:

    ICMPFlowTable(): _flow_table(ICMPFlowEntry()) {}
    ~ICMPFlowTable() { clear(); }

    void add_flow(const IPFlowID & flow_key,
                  unsigned int num_generated,
                  unsigned int pause_interval);
    void remove_flow(const IPFlowID & flow_key);

    ICMPFlowEntry * get_flow(const IPFlowID & flow_key)
                        { return _flow_table.get_pointer(flow_key); }

    void clear() { _flow_table.clear(); }

  private:

    HashTable<IPFlowID, ICMPFlowEntry> _flow_table;

};


// Element that identifies packets to send to an ICMPError element.
// Used for experimental and test purposes.
//

class ICMPGenerator : public Element { public:

    ICMPGenerator();
    ~ICMPGenerator();

    const char *class_name() const	{ return "ICMPGenerator"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int, Packet *);

  private:

    void process_packet(Packet * p, bool reverse, bool sentinel);

    bool syn_packet(Packet * p);
    bool tls_sentinel_packet(Packet * p);
    bool http_sentinel_packet(Packet * p);

    unsigned int _num_generated;
    unsigned int _pause_interval;
    unsigned int _initial_pause;

    bool _reverse;

    ICMPFlowTable _flow_table;
};


CLICK_ENDDECLS
#endif

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

#include <click/config.h>
#include "dr2dpdecoder.hh"
#include "dr2dpprotocol.hh"
#include <click/bitvector.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#if CLICK_LINUXMODULE
#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <linux/fs.h>
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>
#elif CLICK_USERLEVEL
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
CLICK_DECLS


DR2DPDecoder::DR2DPDecoder()
    : _pktbuf((Packet *)NULL), _header_needed(false), _bytes_remaining(0)
{
}

DR2DPDecoder::~DR2DPDecoder()
{
    release_pkt_buffer();
}

int
DR2DPDecoder::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); i++) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0 || parts.size() > 2) {
            errh->error("conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DETECTOR", strlen("DETECTOR"))) {
            Element *e = cp_element(parts[1], this, errh);
            if (e != NULL ) {
                _configured_detectors.push_back(e);
            } else {
                errh->error("invalid element");
            }

        } else if (parts[0].equals("FILTER_FILENAME",
                                   strlen("FILTER_FILENAME"))) {
            _filter_file = parts[1];

        } else if (parts[0].equals("BLACKLIST_FILENAME",
                                   strlen("BLACKLIST_FILENAME"))) {
            _dh_blacklist_file = parts[1];

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
DR2DPDecoder::initialize(ErrorHandler *)
{
    for (Vector<Element *>::iterator e = _configured_detectors.begin();
         e != _configured_detectors.end();
         ++e) {

        if ((*e)->cast("SentinelDetector")) {
            SentinelDetector *d = (SentinelDetector *)(*e);
            if (_filter_file.length() > 0) {
	        d->update_sentinel_filter(&_sentinels);
            }
            _sentinel_detectors.push_back(d);
        }
    }

    return 0;
}

void
DR2DPDecoder::push(int, Packet *p)
{
    parse(p);
}

void
DR2DPDecoder::parse(Packet *p)
{
    bool done = false;
    while (!done) {
        // Handle partial DR2DP message.
        if (_pktbuf != NULL) {
            p = append_to_pkt_buffer(p);
            if (p == NULL) {
                return;
            }
        }

        const dr2dp_msg *msg = reinterpret_cast<const dr2dp_msg *>(p->data());

        if (p->length() < sizeof(dr2dp_msg)) {
            // Entire DR2DP message header not present;
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(p);
            return;
        }

        if (msg->protocol != DR2DP_PROTOCOL_VERSION) {
            click_chatter("DR2DPDecoder::parse: "
                          "Invalid DR2DP protocol version %d", msg->protocol);
            p->kill();
            return;
        }

        Packet *pkt = p;
        bool release_pkt = true;
        uint64_t pkt_length = sizeof(dr2dp_msg) + ntohq(msg->data_length);

        if (pkt->length() < pkt_length) {
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(pkt, pkt_length);
            return;

        } else if (pkt->length() > pkt_length) {
            // DR2DP message accounts for only part of the packet buffer.
            pkt = WritablePacket::make(0, p->data(), pkt_length, 0);
            if (pkt == NULL) {
                click_chatter("DR2DPDecoder::parse: "
                              "failed to allocate new packet");
                p->kill();
                return;
            }
            p->pull(pkt_length);

        } else { // pkt->length() == pkt_length
            done = true;
        }

        // Process a fully recieved DR2DP message.
        switch (msg->operation_type) {

        // Ping message.
        case DR2DP_OP_TYPE_PING:
            click_chatter("DR2DPDecoder::parse: ping message received");
            break;

        // Packet to be forwarded on behalf of decoy proxy.
        case DR2DP_OP_TYPE_FORWARD:
            if (msg->message_type != DR2DP_MSG_TYPE_REQUEST) {
                click_chatter("DR2DPDecoder::parse: "
                              "Invalid message type for forward operation.");
                break;
            }

            forward_packet(pkt);
            release_pkt = false;
            break;

        // New sentinel bloom filter to upload.
        case DR2DP_OP_TYPE_SENTINEL_FILTER:
            parse_filter_msg(pkt);
            break;

        case DR2DP_OP_TYPE_REMOVE_FLOW:
            if (msg->message_type != DR2DP_MSG_TYPE_REQUEST) {
                click_chatter("DR2DPDecoder::parse: "
                              "Invalid message type for remove operation.");
                break;
            }
            parse_remove_flow_msg(pkt);
            break;

        case DR2DP_OP_TYPE_DH_BLACKLIST:
            parse_dh_blacklist_msg(pkt);
            break;

        default:
            click_chatter("DR2DPDecoder::parse: "
                          "Unsupported DR2DP operation type %d",
                          msg->operation_type);
            break;
        }

        if (release_pkt) {
            // No longer need the packet data; release memory.
            pkt->kill();
        }
    }
}

void
DR2DPDecoder::parse_filter_msg(Packet *p)
{
    if (_filter_file.length() == 0) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No filter file. ");
        return;
    }

    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No sentinel detector.");
        return;
    }

    const dr2dp_msg *msg_hdr = reinterpret_cast<const dr2dp_msg *>(p->data());

    uint64_t data_length = ntohq(msg_hdr->data_length);
    if (data_length < sizeof(dr2dp_filter_msg)) {
        click_chatter("DR2DPDecoder::parse_filter_msg: Message not complete.");
        return;
    }

    p->pull(sizeof(dr2dp_msg));
    const dr2dp_filter_msg *msg =
        reinterpret_cast<const dr2dp_filter_msg *>(p->data());

    Vector<uint32_t> salt_values;
    unsigned int num_salts = ntohs(msg->num_salts);

    uint32_t salt_length = data_length - sizeof(dr2dp_filter_msg);
    uint32_t *salt = (uint32_t *)(p->data() + sizeof(dr2dp_filter_msg));

    if (salt_length != num_salts * sizeof(uint32_t)) {
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "Invalid message length.");
        return;
    }

    for (unsigned int i = 0; i < num_salts; ++i, ++salt) {
        salt_values.push_back(ntohl(*salt));
    }

    int hash_size = ntohs(msg->hash_size);
    if (hash_size < 0 || hash_size > 30) {
        click_chatter("DR2DPDecoder::parse_filter_msg: Invalid hash size %d",
                      hash_size);
        return;
    }

    if (hash_size == 0) {
        _sentinels = BloomFilter();
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "loading empty sentinel bloom filter");
        return;
    }

    bool valid = true;
    int total_bits = BloomFilter::bit_vector_size(hash_size);
    Bitvector bit_vector(total_bits);
    uint32_t *bit_data = bit_vector.words();

#if CLICK_USERLEVEL
    int fd = open(_filter_file.c_str(), O_RDONLY);
    if (fd < 0) {
        click_chatter("DR2DDecoder::parse_filter_msg: "
                      "failed to open filter file %s", _filter_file.c_str());
        valid = false;

#elif CLICK_LINUXMODULE
    struct file* filp = (struct file *)NULL;
    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    filp = filp_open(_filter_file.c_str(), 0, O_RDONLY);
    if (IS_ERR(filp) || filp == NULL) {
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "failed to open filter file %s", _filter_file.c_str());
        filp = (struct file *)NULL;
        valid = false;
#endif

    } else {

        int read_bytes;
        int remaining_bytes = ((total_bits < 8)? 1 : (total_bits / 8));
        uint8_t buf[256];

        while(remaining_bytes > 0) {

#if CLICK_USERLEVEL
            read_bytes = read(fd, buf, 256);
#elif CLICK_LINUXMODULE
            read_bytes = vfs_read(filp, (char *)buf, 256, &filp->f_pos);
#endif

            if (read_bytes < 0) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Error reading filter");
                valid = false;
                break;

            } else if (read_bytes == 0) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Filter too small");
                valid = false;
                break;

            } else if (read_bytes > remaining_bytes) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Filter too large");
                valid = false;
                break;
            }

            memcpy(bit_data, buf, read_bytes);

            bit_data += (read_bytes / 4);
            remaining_bytes -= read_bytes;
        }
    }

#if CLICK_USERLEVEL
    if (fd >= 0) {
        close(fd);
    }

#elif CLICK_LINUXMODULE
    if (filp != NULL) {
        filp_close(filp, (fl_owner_t)NULL);
        filp = (struct file *)NULL;
    }
    set_fs(oldfs);
#endif

    if (valid) {
	_sentinels = BloomFilter(hash_size, bit_vector, salt_values);
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "uploaded new sentinel bloom filter");

    } else {
	_sentinels = BloomFilter();
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "invalid sentinel bloom filter; loading empty filter");
    }
}

void
DR2DPDecoder::parse_remove_flow_msg(Packet *p)
{
    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No sentinel detector.");
        return;
    }

    const dr2dp_msg *msg_hdr = reinterpret_cast<const dr2dp_msg *>(p->data());

    uint64_t data_length = ntohq(msg_hdr->data_length);
    if (data_length < sizeof(dr2dp_remove_flow_msg)) {
        click_chatter("DR2DPDecoder::parse_remove_flow_msg: "
                      "Message not complete.");
        return;
    }

    p->pull(sizeof(dr2dp_msg));
    const dr2dp_remove_flow_msg *msg =
        reinterpret_cast<const dr2dp_remove_flow_msg *>(p->data());

    // addrs/ports required to be in network byte order
    IPFlowID flow_id(IPAddress(msg->src_addr), msg->src_port,
                     IPAddress(msg->dst_addr), msg->dst_port);

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {
        (*d)->remove_flow(flow_id);
    }
}

void
DR2DPDecoder::parse_dh_blacklist_msg(Packet *)
{
    if (_dh_blacklist_file.length() == 0) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "no blacklist file configured");
        return;
    }

    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "no sentinel detectors configured");
        return;
    }

    Vector<DHBlacklistEntry> blacklist;

#if CLICK_USERLEVEL
    FILE *fp = fopen(_dh_blacklist_file.c_str(), "r");
    if (fp == NULL) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "failed to open blacklist file %s",
                      _dh_blacklist_file.c_str());

    } else {
        char *line = NULL;
        size_t line_length = 0;

        while (getline(&line, &line_length, fp) != -1) {
	    // assume the maximum possible match length
	    char *addr = (char *) malloc(line_length + 1);
	    char *mask = (char *) malloc(line_length + 1);
            int n;

	    assert(addr != NULL);
	    assert(mask != NULL);

	    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: [%s]", line);

            n = sscanf(line, "%s %s", addr, mask);
            if (n == 1) {
                struct in_addr ipaddr;

                if (inet_aton(addr, &ipaddr) != 0) {

                    IPAddress new_addr(ipaddr);
                    DHBlacklistEntry entry(new_addr);
                    blacklist.push_back(entry);

                } else {
                    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                  "invalid IP address: %s", addr); 
                }

            } else if (n == 2) {
                struct in_addr ipaddr;
                struct in_addr ipmask;

                if ((inet_aton(addr, &ipaddr) != 0) &&
                    (inet_aton(mask, &ipmask) != 0)) {

                    IPAddress new_addr(ipaddr);
                    IPAddress new_mask(ipmask);

                    if (new_mask.mask_to_prefix_len() == -1) {
                        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                      "invalid mask: %s", mask);
                    } else {
                        DHBlacklistEntry entry(new_addr, new_mask);
                        blacklist.push_back(entry);
                    }

                } else {
                    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                  "invalid IP address/mask: %s %s",
                                  addr, mask);
                }


            } else {
                click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                              "failed to parse blacklist line: %s", line);
            }

	    free(addr);
	    free(mask);
            free(line);
            line = NULL;
            line_length = 0;
        }

        fclose(fp);
    }

#elif CLICK_LINUXMODULE
    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                  "loading of DH blacklist not supported in kernel mode");

#endif

    _dh_blacklist = blacklist;

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {
        (*d)->update_dh_blacklist(_dh_blacklist);
    }

    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                  "uploaded new DH blacklist");
}

void
DR2DPDecoder::forward_packet(Packet *p)
{
    // remove DR2DP protocol message header
    p->pull(sizeof(dr2dp_msg));

    // set network and transport headers
    assert(p->length() > sizeof(click_ip));

    const click_ip *ip_hdr = (const click_ip *)(p->data());
    unsigned int ip_hlen = ip_hdr->ip_hl << 2;

    assert(p->length() >= (ip_hlen + 4)); // header length plus ports

    p->set_network_header(p->data());
    p->set_transport_header(p->data() + ip_hlen);

    // find flow entry for packet
    FlowEntry *flow_entry = NULL;
    bool reverse = retrieve_flow_entry(p, &flow_entry);

    if (flow_entry == NULL) {
        click_chatter("DR2DPDecoder::forward_packet: "
                      "packet failed to match a redirected flow");
        p->kill();
        return;
    }

    // avoid fastclick warning; shift so packet is at start of data buffer
    int ether_len = (flow_entry->vlan() ? sizeof(click_ether_vlan) :
                                          sizeof(click_ether)); 
    int shift_len = p->headroom() - ether_len;
    assert(shift_len >= 0);

    p = p->shift_data(-shift_len);
    if (p == NULL) {
        click_chatter("DR2DPDecoder::forward_packet: "
                      "failed to shift packet data");
        p->kill();
        return;
    }
    
    Packet *fwd_pkt = NULL;

    // add ethernet header with vlan tag
    if (flow_entry->vlan()) {
        fwd_pkt = p->push(sizeof(click_ether_vlan));
        click_ether_vlan *ether_hdr = (click_ether_vlan *)(fwd_pkt->data());
        ether_hdr->ether_vlan_proto = htons(ETHERTYPE_8021Q);
        ether_hdr->ether_vlan_tci = flow_entry->vlan_tag();
        ether_hdr->ether_vlan_encap_proto = htons(ETHERTYPE_IP);

    } else { // traditional ethernet
        fwd_pkt = p->push(sizeof(click_ether));
        click_ether *ether_hdr = (click_ether *)(fwd_pkt->data());
        ether_hdr->ether_type = htons(ETHERTYPE_IP);
    }

    click_ether *ether_hdr = (click_ether *)(fwd_pkt->data());

    if (!reverse) {
        memcpy(&ether_hdr->ether_shost,
               flow_entry->get_src_ethernet().data(),
               sizeof(ether_hdr->ether_shost));
        memcpy(&ether_hdr->ether_dhost,
               flow_entry->get_dst_ethernet().data(),
               sizeof(ether_hdr->ether_dhost));

    } else { // reverse
        memcpy(&ether_hdr->ether_shost,
               flow_entry->get_dst_ethernet().data(),
               sizeof(ether_hdr->ether_shost));
        memcpy(&ether_hdr->ether_dhost,
               flow_entry->get_src_ethernet().data(),
               sizeof(ether_hdr->ether_dhost));
    }

    // push packet out the element's outbound interfaces
    if (!reverse) {
        output(0).push(fwd_pkt);

    } else { // reverse
        output(1).push(fwd_pkt);
    }
}

bool
DR2DPDecoder::retrieve_flow_entry(Packet *p, FlowEntry **entry)
{
    IPFlowID flow_key;
    bool icmp_pkt = false;

    if (p->ip_header()->ip_p != IP_PROTO_ICMP) {
        flow_key = IPFlowID(p);

    // icmp packet
    } else {
        // the decoy proxy should only have received (and forward) icmp
        // packets with embedded ip packets that match redirected flows;
        // nothing to do otherwise

        if ((unsigned int)p->transport_length() < sizeof(click_icmp)) {
            *entry = NULL;
            return false;
        }

        const unsigned char *data = p->transport_header() + sizeof(click_icmp);
        unsigned int len = p->transport_length() - sizeof(click_icmp);

        if (len < sizeof(click_ip)) {
            *entry = NULL;
            return false;
        }

        const click_ip *ip_hdr = (const click_ip *)data;
        unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

        if (len < ip_hdr_len + sizeof(click_tcp)) {
            *entry = NULL;
            return false;
        }

        const click_tcp *tcp_hdr = (const click_tcp *)(data + ip_hdr_len);

        flow_key = IPFlowID(IPAddress(ip_hdr->ip_src), tcp_hdr->th_sport,
                            IPAddress(ip_hdr->ip_dst), tcp_hdr->th_dport);
        icmp_pkt = true;
    }

    FlowEntry *flow_entry = NULL;
    bool reverse = false;

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {

        flow_entry = (*d)->retrieve_flow_entry(flow_key);
        if (flow_entry != NULL) {
            if (icmp_pkt) {  // icmp packets go in reverse direction
                reverse = true;
            }
            break;
        }

        flow_entry = (*d)->retrieve_flow_entry(flow_key.reverse());
        if (flow_entry != NULL) {
            if (!icmp_pkt) {  // icmp packets go in reverse direction
                reverse = true;
            }
            break;
        }
    }

    *entry = flow_entry;
    return reverse;
}

void
DR2DPDecoder::new_pkt_buffer(Packet *p, uint64_t length_needed)
{
    assert(_pktbuf == NULL);
    assert(length_needed == 0 || length_needed > p->length());

    _pktbuf = p;
    set_prev_pkt(_pktbuf, (Packet *) NULL);
    set_next_pkt(_pktbuf, (Packet *) NULL);

    if (length_needed == 0) {
        _header_needed = true;
        _bytes_remaining = sizeof(dr2dp_msg) - p->length();

    } else {
        _bytes_remaining = length_needed - p->length();
    }
}

Packet *
DR2DPDecoder::append_to_pkt_buffer(Packet *p)
{
    assert(_pktbuf != NULL);
    assert(_bytes_remaining > 0);

    if (_header_needed) {
        if (_bytes_remaining > p->length()) {
            add_pkt(p);
            p = (Packet *)NULL;
            return p;
        }

        dr2dp_msg msg_hdr;
        memset(&msg_hdr, 0, sizeof(dr2dp_msg));

        // Build complete copy of DR2DP message header.
        Packet *pkt = _pktbuf;
        unsigned char *cur_pos = (unsigned char *)&msg_hdr;
        do {
            memcpy(cur_pos, pkt->data(), pkt->length());
            cur_pos += pkt->length();
            pkt = next_pkt(pkt);
        } while (pkt != _pktbuf && pkt != NULL);

        assert((cur_pos + _bytes_remaining) ==
               ((unsigned char *)&msg_hdr + sizeof(dr2dp_msg)));

        memcpy(cur_pos, p->data(), _bytes_remaining);

        _bytes_remaining += ntohq(msg_hdr.data_length);
        _header_needed = false;
    }

    if (_bytes_remaining >= p->length()) {
        add_pkt(p);
        p = (Packet *)NULL;

    } else {
        int max_ether_len = sizeof(click_ether_vlan);
        Packet * pkt = WritablePacket::make(
            max_ether_len, p->data(), _bytes_remaining, 0);
        
        p->pull(_bytes_remaining);
        
        if (pkt == NULL) {
            click_chatter("DR2DPDecoder::append_to_pkt_buffer: "
                          "failed to allocate new packet");
            release_pkt_buffer();
            return p;
        }        

        add_pkt(pkt);
        assert(_bytes_remaining == 0);
    }

    if (_bytes_remaining == 0) {
        process_pkt_buffer();
    }

    return p;
}

void
DR2DPDecoder::add_pkt(Packet *p)
{
    assert(_pktbuf);

    if (prev_pkt(_pktbuf) == NULL) {
        assert(next_pkt(_pktbuf) == NULL);

        set_next_pkt(_pktbuf, p);
        set_prev_pkt(_pktbuf, p);
        set_next_pkt(p, _pktbuf);
        set_prev_pkt(p, _pktbuf);

    } else {
        assert(prev_pkt(_pktbuf) != NULL);
        assert(next_pkt(_pktbuf) != NULL);

        set_next_pkt(prev_pkt(_pktbuf), p);
        set_prev_pkt(p, prev_pkt(_pktbuf));
        set_prev_pkt(_pktbuf, p);
        set_next_pkt(p, _pktbuf);
    }

    _bytes_remaining -= p->length();
}

Packet *
DR2DPDecoder::next_pkt(Packet *p) const
{
    assert(p);
    return (Packet *) p->anno_ptr(NEXT_PKT_INDEX);
}

Packet *
DR2DPDecoder::prev_pkt(Packet *p) const
{
    assert(p);
    return (Packet *) p->anno_ptr(PREV_PKT_INDEX);
}

void
DR2DPDecoder::set_next_pkt(Packet *p, Packet *next)
{
    assert(p);
    p->set_anno_ptr(NEXT_PKT_INDEX, (const void *)next);
}

void
DR2DPDecoder::set_prev_pkt(Packet *p, Packet *prev)
{
    assert(p);
    p->set_anno_ptr(PREV_PKT_INDEX, (const void *)prev);
}

void
DR2DPDecoder::process_pkt_buffer()
{
    assert(_header_needed == false);
    assert(_bytes_remaining == 0);
    assert(next_pkt(_pktbuf) != NULL);

    uint64_t orig_len = _pktbuf->length();
    uint64_t curr_len = _pktbuf->length();

    uint64_t data_len_to_add = 0;
    for (Packet *p = next_pkt(_pktbuf); p != _pktbuf; p = next_pkt(p)) {
        data_len_to_add += p->length();
    }

    // Remove first packet from buffer.
    Packet * first_pkt = _pktbuf;
    set_next_pkt(prev_pkt(_pktbuf), next_pkt(_pktbuf));
    set_prev_pkt(next_pkt(_pktbuf), prev_pkt(_pktbuf));
    _pktbuf = next_pkt(_pktbuf);
    set_next_pkt(first_pkt, (Packet *) NULL);
    set_prev_pkt(first_pkt, (Packet *) NULL);

    // Create new packet to contain the total assembled DR2DP message.
    WritablePacket *pkt = (WritablePacket *)first_pkt;

    if (first_pkt->tailroom() < (data_len_to_add + 128)) {
        pkt = WritablePacket::make(
                  0, first_pkt->data(), first_pkt->length(), data_len_to_add);

        // new packet copy made; no longer need the original
        first_pkt->kill();

        if (pkt == NULL) {
            click_chatter("DR2DPDecoder::process_pkt_buffer: "
                          "failed to allocate new packet");
            release_pkt_buffer();
            return;
        }
    }

    pkt = pkt->put(data_len_to_add);
    if (pkt == NULL) {
        click_chatter("DR2DPDecoder::process_pkt_buffer: "
                      "failed to increase packet size");
        release_pkt_buffer();
        return;
    }

    // Copy message pieces from remaining packets to new packet buffer.
    Packet *p = _pktbuf;
    unsigned char * end_data = pkt->data() + curr_len;
    do {
        memcpy(end_data, p->data(), p->length());
        end_data += p->length();
        curr_len += p->length();
        p = next_pkt(p);
    } while (p != _pktbuf);

    if (curr_len != orig_len + data_len_to_add) {
        click_chatter("DR2DPDecoder::process_pkt_buffer: "
                      "packet lengths fail to match");
        return;
    }

    release_pkt_buffer();

    // Process complete DR2DP message.
    parse(pkt);
}

void
DR2DPDecoder::release_pkt_buffer()
{
    _header_needed = false;
    _bytes_remaining = 0;

    if (_pktbuf == NULL) {
        return;
    }

    if (prev_pkt(_pktbuf) != NULL) {
        set_next_pkt(prev_pkt(_pktbuf), (Packet *) NULL);
    }

    Packet * p = _pktbuf;
    Packet * tmp = (Packet *)NULL;

    while (p != NULL) {
        tmp = p;
        p = next_pkt(p);
        tmp->kill();
    }

    _pktbuf = (Packet *)NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DR2DPDecoder)

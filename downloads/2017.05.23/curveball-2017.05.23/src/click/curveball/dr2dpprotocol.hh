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

#ifndef CURVEBALL_DR2DPPROTOCOL_HH
#define CURVEBALL_DR2DPPROTOCOL_HH
CLICK_DECLS


// DR2DP protocol message header
struct dr2dp_msg {
#define DR2DP_PROTOCOL_VERSION          	2
    uint8_t     protocol;
    uint8_t     session_type;
#define DR2DP_MSG_TYPE_REQUEST          	1
#define DR2DP_MSG_TYPE_RESPONSE         	2
    uint8_t     message_type;
#define DR2DP_OP_TYPE_PING              	1
#define DR2DP_OP_TYPE_FORWARD           	2
#define DR2DP_OP_TYPE_SENTINEL_FILTER   	3
#define DR2DP_OP_TYPE_REDIRECT_FLOW		4
#define DR2DP_OP_TYPE_REMOVE_FLOW		5
#define DR2DP_OP_TYPE_REASSIGN_FLOW		6
#define DR2DP_OP_TYPE_TLS_FLOW_ESTABLISHED	7
#define DR2DP_OP_TYPE_ICMP			8
// DR-only types (Click <--> user space DR communication)
#define DR2DP_OP_TYPE_DH_BLACKLIST		10
    uint8_t     operation_type;
    uint32_t    response_code;
    uint64_t    xid;
    uint64_t    data_length;
};

// DR2DP SENTINEL_FILTER message
struct dr2dp_filter_msg {
    uint16_t    hash_size;
    uint16_t    num_salts;
/*
    uint32_t    salts[num_salts];
*/
};

// DR2DP REDIRECT_FLOW message
struct dr2dp_redirect_flow_msg {
#define DR2DP_REDIRECT_FLAG_ACK		0x0001
    uint16_t	flags;
    uint8_t	syn_option_length;
    uint8_t	ack_option_length;
/*
    uint8_t	syn_tcp_options[syn_options_length];
    uint8_t	ack_tcp_options[ack_options_length];
    uint8_t	sentinel_packets[];
*/
};

// DR2DP REMOVE_FLOW message
struct dr2dp_remove_flow_msg {
    uint32_t	src_addr;
    uint32_t	dst_addr;
    uint16_t	src_port;
    uint16_t	dst_port;
    uint8_t	protocol;
    uint8_t     padding[3];
};

// DR2DP TLS_FLOW_ESTABLISHED message
struct dr2dp_tls_flow_msg {
    uint32_t	src_addr;
    uint32_t	dst_addr;
    uint16_t	src_port;
    uint16_t	dst_port;
    uint8_t	protocol;
    uint8_t     padding[3];
    uint8_t	random_number[28];
};

// DR2DP ICMP message
struct dr2dp_icmp_msg {
    uint32_t	src_addr;
    uint32_t	dst_addr;
    uint16_t	src_port;
    uint16_t	dst_port;
    uint8_t	protocol;
#define DR2DP_ICMP_FLAG_TO_CLIENT	0x01
    uint8_t     flags;
    uint16_t	padding;
/*
    uint8_t	icmp_packet[];
*/
};

// UDP flow notification message
struct dr_flow_notification_msg {
    uint8_t	dr_sentinel[8];
    uint32_t	src_addr;
    uint32_t	dst_addr;
    uint16_t	src_port;
    uint16_t    dst_port;
    uint16_t    flow_sentinel_length;
    uint16_t 	padding;
/*
    uint8_t	flow_sentinel[flow_sentinel_length];
*/
};

CLICK_ENDDECLS
#endif

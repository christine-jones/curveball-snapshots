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

require(package "curveball");

define($FORWARD_DEV netmap:eth4,
       $REVERSE_DEV netmap:eth5,
       $TLS_PORT 443,
       $HTTP_PORT 80,
       $UDP_PORT 9,
       $UDP_SRC_ADDR 10.0.0.32,
       $PATH '/tmp/curveball')

forward_classifier :: Classifier(12/0800, -)
reverse_classifier :: Classifier(12/0800, -)

forward_ip_classifier :: IPClassifier(dst tcp port $TLS_PORT,
                                      dst tcp port $HTTP_PORT,
                                      icmp,
                                      dst udp port $UDP_PORT,
                                      -)

reverse_ip_classifier :: IPClassifier(icmp, -)

tls_flow_detector	:: TLSFlowDetector(PORT $TLS_PORT,
                                           ENCODER dr2dp_encoder,
                                           UDP_PORT $UDP_PORT,
                                           UDP_SRC_ADDR $UDP_SRC_ADDR,
                                           REVERSE false)
http_flow_detector	:: HTTPFlowDetector(PORT $HTTP_PORT,
                                            ENCODER dr2dp_encoder,
                                            UDP_PORT $UDP_PORT,
                                            UDP_SRC_ADDR $UDP_SRC_ADDR,
                                            REVERSE false)

forward_icmp_processor	:: ICMPProcessor(DETECTOR tls_flow_detector,
                                         DETECTOR http_flow_detector);
reverse_icmp_processor	:: ICMPProcessor(DETECTOR tls_flow_detector,
                                         DETECTOR http_flow_detector);

udp_receiver		:: UDPReceiver(PORT $UDP_PORT,
                                       IPADDR $UDP_SRC_ADDR,
                                       DETECTOR tls_flow_detector,
                                       DETECTOR http_flow_detector);

dr2dp_encoder :: DR2DPEncoder()
dr2dp_decoder :: DR2DPDecoder(DETECTOR tls_flow_detector,
                              DETECTOR http_flow_detector,
                              FILTER_FILENAME /tmp/sentinel_filter,
                              BLACKLIST_FILENAME /tmp/bad_dh_list)

decoy_proxy :: Socket(UNIX, $PATH, CLIENT true, HEADROOM 0)

forward_incoming :: FromNetmapDevice($FORWARD_DEV, PROMISC true)
forward_outgoing :: ToNetmapDevice($REVERSE_DEV)
forward_incoming -> forward_classifier;

reverse_incoming :: FromNetmapDevice($REVERSE_DEV, PROMISC true)
reverse_outgoing :: ToNetmapDevice($FORWARD_DEV)
reverse_incoming -> reverse_classifier;

// IPv4 traffic
forward_classifier[0]
	-> CBStripEther()
	-> MarkIPHeader()
	-> forward_ip_classifier;
reverse_classifier[0]
	-> CBStripEther()
	-> MarkIPHeader()
	-> reverse_ip_classifier;

// non-IPv4 traffic
forward_classifier[1] -> forward_outgoing;
reverse_classifier[1] -> reverse_outgoing;

// TLS
forward_ip_classifier[0]
	-> [0]tls_flow_detector;

Idle -> [1]tls_flow_detector;	// no incoming reverse traffic

tls_flow_detector[0]		// Curveball
	-> dr2dp_encoder
	-> decoy_proxy;

tls_flow_detector[1]		// Non-Curveball
	-> CBUnstripEther()
	-> forward_outgoing;

tls_flow_detector[2]		// UDP Notifications
	-> forward_outgoing;

tls_flow_detector[3]		// Reverse Traffic
	-> CBUnstripEther()
	-> reverse_outgoing;

// HTTP
forward_ip_classifier[1]
	-> [0]http_flow_detector;

Idle -> [1]http_flow_detector;	// no incoming reverse traffic

http_flow_detector[0]		// Curveball
	-> dr2dp_encoder
	-> decoy_proxy;

http_flow_detector[1]		// Non-Curveball
	-> CBUnstripEther()
	-> forward_outgoing;

http_flow_detector[2]		// UDP Notifications
	-> forward_outgoing;

http_flow_detector[3]		// Reverse Traffic
	-> CBUnstripEther()
	-> reverse_outgoing;

// ICMP
forward_ip_classifier[2]
	-> forward_icmp_processor
	-> CBUnstripEther()
	-> forward_outgoing;

reverse_ip_classifier[0]
	-> reverse_icmp_processor
	-> CBUnstripEther()
	-> reverse_outgoing;

// UDP
forward_ip_classifier[3]
	-> udp_receiver
	-> CBUnstripEther()
	-> forward_outgoing;

// everything else
forward_ip_classifier[4] -> CBUnstripEther() -> forward_outgoing;
reverse_ip_classifier[1] -> CBUnstripEther() -> reverse_outgoing;

// handle data/packets received from the decoy proxy
decoy_proxy -> dr2dp_decoder;

dr2dp_decoder[0] -> forward_outgoing;
dr2dp_decoder[1] -> reverse_outgoing;

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

require(package "curveball");

define($DEV eth0,
       $REVERSE_DEV eth2,
       $LOCAL_IP 10.1.1.3,
       $REVERSE_IP 10.1.2.2,
       $PATH '/tmp/curveball',
       $TLS_PORT 443,
       $HTTP_PORT 80,
       $BITTORRENT_PORT 6881,
       $UDP_PORT 9,
       $DROP_INTERVAL 30)

ip_classifier	:: IPClassifier(
                     dst tcp port $TLS_PORT,
                     dst tcp port $HTTP_PORT,
                     dst tcp port $BITTORRENT_PORT,
                     icmp,
                     dst udp port $UDP_PORT,
                     ip proto tcp and not dst host $LOCAL_IP, -)

ip_reverse	:: IPClassifier(
                     src tcp port $TLS_PORT,
                     src tcp port $HTTP_PORT,
                     src tcp port $BITTORRENT_PORT,
                     icmp,
                     ip proto tcp and not dst host $REVERSE_IP, -)

tls_flow_detector	:: TLSFlowDetector(PORT $TLS_PORT,
                                           ENCODER dr2dp_encoder,
                                           UDP_PORT $UDP_PORT,
                                           LOCAL_IPADDR $LOCAL_IP,
                                           REVERSE true)

http_flow_detector	:: HTTPFlowDetector(PORT $HTTP_PORT,
                                            ENCODER dr2dp_encoder,
                                            UDP_PORT $UDP_PORT,
                                            LOCAL_IPADDR $LOCAL_IP,
                                            REVERSE true)

bittorrent_detector	:: BitTorrentDetector(PORT $BITTORRENT_PORT,
                                              ENCODER dr2dp_encoder,
                                              UDP_PORT $UDP_PORT,
                                              LOCAL_IPADDR $LOCAL_IP,
                                              REVERSE true)

dr2dp_encoder		:: DR2DPEncoder(PING 300)
dr2dp_decoder		:: DR2DPDecoder(DETECTOR tls_flow_detector,
                                        DETECTOR http_flow_detector,
                                        DETECTOR bittorrent_detector,
                                        FILTER_FILENAME /tmp/sentinel_filter,
                                        BLACKLIST_FILENAME /tmp/bad_dh_list)

icmp_processor		:: ICMPProcessor(DETECTOR tls_flow_detector,
                                         DETECTOR http_flow_detector)

udp_receiver		:: UDPReceiver(PORT $UDP_PORT,
                                       IPADDR $LOCAL_IP,
                                       DETECTOR tls_flow_detector,
                                       DETECTOR http_flow_detector,
                                       DETECTOR bittorrent_detector)

forward			:: Queue -> RawSocket(TCP)
decoy_proxy		:: Socket(UNIX, $PATH, CLIENT true)

forward_interface 	:: FromDevice($DEV, FORCE_IP true) 
reverse_interface 	:: FromDevice($REVERSE_DEV, FORCE_IP true)

// Set up iptables rule to drop all tcp packets forwarded on given interface
// such that the kernal and user-level click do not both process the packets.
CurveballKernelFilter(drop dev $DEV);
CurveballKernelFilter(drop dev $REVERSE_DEV);

forward_interface 
	-> Strip(14)
	-> CheckIPHeader2()
	-> dec_ttl::DecIPTTL
	-> ip_classifier;

reverse_interface
	-> Strip(14)
	-> CheckIPHeader2()
	-> rev_dec_ttl::DecIPTTL
	-> ip_reverse;

// TLS Traffic
ip_classifier[0]
	-> CheckTCPHeader()
	-> [0]tls_flow_detector;

ip_reverse[0]
	-> CheckTCPHeader()
	-> [1]tls_flow_detector;

tls_flow_detector[0]		// Curveball packet.
	-> dr2dp_encoder
	-> decoy_proxy;

tls_flow_detector[1]		// Non-Curveball packet.
	-> forward;

tls_flow_detector[2]		// UDP flow notifications
	-> forward;

// HTTP Traffic
ip_classifier[1]
	-> CheckTCPHeader()
	-> [0]http_flow_detector;

ip_reverse[1]
	-> CheckTCPHeader()
	-> [1]http_flow_detector;

http_flow_detector[0]		// Curveball packet.
	-> dr2dp_encoder
	-> decoy_proxy;

http_flow_detector[1]		// Non-Curveball packet.
	-> forward;

http_flow_detector[2]		// UDP flow notifications
	-> forward;

// BitTorrent Traffic
ip_classifier[2]
	-> CheckTCPHeader()
	-> [0]bittorrent_detector;

ip_reverse[2]
	-> CheckTCPHeader()
	-> [1]bittorrent_detector;

bittorrent_detector[0]		// Curveball packet
	-> dr2dp_encoder
	-> decoy_proxy;

bittorrent_detector[1]		// Non-Curveball packet
	-> forward;

bittorrent_detector[2]		// UDP flow notifications
	-> forward;

// ICMP Packets
ip_classifier[3]
	-> CheckICMPHeader()
	-> icmp_processor
	-> forward;

ip_reverse[3]
	-> CheckICMPHeader()
	-> icmp_processor
	-> forward;

// UDP Flow Notifications
ip_classifier[4]
	-> CheckUDPHeader()
	-> udp_receiver
	-> forward;

// Forward all non-TLS/HTTP TCP packets. Discard non-TCP packets and packets
// destined to the local host. These are processed by the kernel, i.e., the
// iptables rules do no drop these packets.
ip_classifier[5] -> forward;
ip_classifier[6] -> Discard;

ip_reverse[4] -> forward;
ip_reverse[5] -> Discard;

// The ICMP packet to notify the source of the ttl=0 is already generated
// by the kernel prior to this packet being handed to the click router.
// So nothing to do but drop the packet.
dec_ttl[1] 	-> Discard;
rev_dec_ttl[1] 	-> Discard;

// Handle data/packets received from the Decoy Proxy.
decoy_proxy
	-> dr2dp_decoder
	-> CheckIPHeader2()
	-> forward;

// collect and report statistics, etc.
CBDiagnostics(DEVICE client forward_interface,
              DEVICE decoy reverse_interface,
              DROP_INTERVAL $DROP_INTERVAL);

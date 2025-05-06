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
       $TLS_PORT 443,
       $TLS_SENTINEL "\xDE\xAD\xBE\xEF",
       $HTTP_PORT 80,
       $HTTP_SENTINEL "DEADBEEF",
       $UDP_PORT 9)

forward_classifier	:: Classifier(12/0800, -)
reverse_classifier	:: Classifier(12/0800, -)

ip_classifier	:: IPClassifier(dst tcp port $TLS_PORT,
                                dst tcp port $HTTP_PORT,
                                dst udp port $UDP_PORT,  -)

ip_reverse	:: IPClassifier(src tcp port $TLS_PORT,
                                src tcp port $HTTP_PORT, -)

tls_flow_detector	:: TLSFlowDetector(PORT $TLS_PORT,
                                           SENTINEL $TLS_SENTINEL,
                                           ENCODER dr2dp_encoder,
                                           UDP_PORT $UDP_PORT,
                                           LOCAL_IPADDR $LOCAL_IP,
                                           REVERSE true)

http_flow_detector	:: HTTPFlowDetector(PORT $HTTP_PORT,
                                            SENTINEL $HTTP_SENTINEL,
                                            ENCODER dr2dp_encoder,
                                            UDP_PORT $UDP_PORT,
                                            LOCAL_IPADDR $LOCAL_IP,
                                            REVERSE true)

dr2dp_encoder		:: DR2DPEncoder(PING 300)
dr2dp_decoder		:: DR2DPDecoder(DETECTOR tls_flow_detector,
                                        DETECTOR http_flow_detector,
                                        FILTER_FILENAME /tmp/sentinel_filter)

// The dr2dp_decoder does not include configuration for BLACKLIST_FILENAME
// because there is no kernel implementation yet for reading blacklist files.


udp_receiver		:: UDPReceiver(PORT $UDP_PORT,
                                       IPADDR $LOCAL_IP,
                                       DETECTOR tls_flow_detector,
                                       DETECTOR http_flow_detector)

forward			:: ToHost()
udp_forward		:: ToHost($REVERSE_DEV, TYPE IP)
decoy_proxy_wr		:: ToUserDevice(0, TYPE stream, BURST 0, CAPACITY 64)
Idle -> decoy_proxy_rd  :: ToUserDevice(1)

FromDevice($DEV)
	-> forward_classifier
	-> Strip(14)
	-> CheckIPHeader2()
	-> ip_classifier;

FromDevice($REVERSE_DEV)
	-> reverse_classifier
	-> Strip(14)
	-> CheckIPHeader2()
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
	-> decoy_proxy_wr;

tls_flow_detector[1]		// Non-Curveball packet.
	-> Unstrip(14)
	-> forward;

tls_flow_detector[2]		// UDP flow notifications
	-> udp_forward;

// HTTP Traffic
ip_classifier[1]
	-> CheckTCPHeader()
	-> [0]http_flow_detector;

ip_reverse[1]
	-> CheckTCPHeader()
	-> [1]http_flow_detector;

http_flow_detector[0]		// Curveball packet.
	-> dr2dp_encoder
	-> decoy_proxy_wr;

http_flow_detector[1]		// Non-Curveball packet.
	-> Unstrip(14)
	-> forward;

http_flow_detector[2]		// UDP flow notifications
	-> udp_forward;

// UDP Flow Notifications
ip_classifier[3]
	-> CheckUDPHeader()
	-> udp_receiver
	-> forward;

forward_classifier[1] -> forward;		// Non-IP packet.
reverse_classifier[1] -> forward;

ip_classifier[3] -> Unstrip(14) -> forward;	// Non-TLS/HTTP packet.
ip_reverse[2] -> Unstrip(14) -> forward;

// Handle data/packets received from the Deocy Proxy.
FromUserDevice(decoy_proxy_rd)
	-> Unqueue
	-> dr2dp_decoder
	-> CheckIPHeader2()
	-> ToHost($DEV, TYPE IP);

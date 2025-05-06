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
       $REVERSE_DEV eth1,
       $LOCAL_IP 10.1.1.3,
       $REVERSE_IP 10.1.2.2,
       $PATH '/tmp/curveball',
       $PORT 443,
       $SENTINEL "\xDE\xAD\xBE\xEF",
       $UDP_PORT 9)

ip_classifier :: IPClassifier(dst tcp port $PORT,
                              dst udp port $UDP_PORT,
                              ip proto tcp and not dst host $LOCAL_IP, -)

ip_reverse    :: IPClassifier(src tcp port $PORT,
                              ip proto tcp and not dst host $REVERSE_IP, -)
             
tls_flow_detector	:: TLSFlowDetector(PORT $PORT,
                                           SENTINEL $SENTINEL,
                                           ENCODER dr2dp_encoder,
                                           UDP_PORT $UDP_PORT,
                                           LOCAL_IPADDR $LOCAL_IP,
                                           REVERSE true)

dr2dp_encoder		:: DR2DPEncoder()
dr2dp_decoder		:: DR2DPDecoder(DETECTOR tls_flow_detector,
                                        FILTER_FILENAME /tmp/sentinel_filter)

udp_receiver		:: UDPReceiver(PORT $UDP_PORT,
                                       IPADDR $LOCAL_IP,
                                       DETECTOR tls_flow_detector)

forward			:: Queue -> RawSocket(TCP)
decoy_proxy		:: Socket(UNIX, $PATH, CLIENT true)

// Set up iptables rule to drop all tcp packets forwarded on given interface
// such that the kernal and user-level click do not both process the packets.
CurveballKernelFilter(drop dev $DEV);
CurveballKernelFilter(drop dev $REVERSE_DEV);

FromDevice($DEV, FORCE_IP true, METHOD LINUX) 
	-> Strip(14)
	-> CheckIPHeader2()
	-> ip_classifier
	-> CheckTCPHeader()
	-> tls_flow_detector;

FromDevice($REVERSE_DEV, FORCE_IP true, METHOD LINUX)
	-> Strip(14)
	-> CheckIPHeader2()
	-> ip_reverse
	-> CheckTCPHeader()
	-> [1]tls_flow_detector;

tls_flow_detector[0]		// Curveball packet.
	-> dr2dp_encoder
	-> decoy_proxy;

tls_flow_detector[1]		// Non-Curveball packet.
	-> forward;

tls_flow_detector[2]		// UDP flow notifications
	-> forward;

// UDP Flow Notifications
ip_classifier[1]
	-> CheckUDPHeader()
	-> udp_receiver
	-> forward;

// Forward all non-TLS TCP packets. Discard non-TCP packets and packets
// destined to the local host. These are processed by the kernel, i.e.,
// the iptables rules do not drop these packets.
ip_classifier[2] -> forward;
ip_classifier[3] -> Discard;

ip_reverse[1] -> forward;
ip_reverse[2] -> Discard;

// Handle data/packets received from the Decoy Proxy.
decoy_proxy
	-> dr2dp_decoder
	-> CheckIPHeader2()
	-> forward;

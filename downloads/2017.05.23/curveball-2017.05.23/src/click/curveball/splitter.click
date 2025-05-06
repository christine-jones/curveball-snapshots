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
       $LOCAL_IP 10.0.0.1,
       $SEGMENT_SIZE 10,
       $SEGMENT_ALL false,
       $REVERSE false,
       $MIX_IT_UP false)

ip_classifier	:: IPClassifier(dst tcp port 443 or dst tcp port 80,
                                ip proto tcp and not dst host $LOCAL_IP, -)

splitter		:: Splitter(SEGMENT_SIZE $SEGMENT_SIZE,
                                    SEGMENT_ALL $SEGMENT_ALL,
                                    REVERSE $REVERSE,
                                    MIX_IT_UP $MIX_IT_UP);

forward			:: Queue -> RawSocket(TCP)

// Set up iptables rule to drop all tcp packets forwarded on given interface
// such that the kernal and user-level click do not both process the packets.
CurveballKernelFilter(drop dev $DEV);

FromDevice($DEV, FORCE_IP true, METHOD LINUX) 
	-> Strip(14)
	-> CheckIPHeader()
	-> dec_ttl::DecIPTTL
	-> ip_classifier;

ip_classifier[0]
	-> CheckTCPHeader()
	-> splitter
	-> SetTCPChecksum()
	-> SetIPChecksum()
	-> forward;

// Forward all non-TLS/HTTP TCP packets. Discard non-TCP packets and packets
// destined to the local host. These are processed by the kernel, i.e., the
// iptables rules do no drop these packets.
ip_classifier[1] -> forward;
ip_classifier[2] -> Discard;

// The ICMP packet to notify the source of the ttl=0 is already generated
// by the kernel prior to this packet being handed to the click router.
// So nothing to do but drop the packet.
dec_ttl[1] 	-> Discard;

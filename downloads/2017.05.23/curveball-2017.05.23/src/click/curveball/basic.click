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

define($DEV eth1,
       $LOCAL_IP 10.0.2.2)

ip_classifier	:: IPClassifier(ip proto tcp and not dst host $LOCAL_IP, -)

forward			:: Queue -> RawSocket(TCP)

// Set up iptables rule to drop all tcp packets forwarded on given interface
// such that the kernal and user-level click do not both process the packets.
CurveballKernelFilter(drop dev $DEV);

FromDevice($DEV, FORCE_IP true, METHOD LINUX) 
	-> Strip(14)
	-> CheckIPHeader()
	-> ip_classifier;

// Forward all traversing TCP packets. Discard non-TCP packets and packets
// destined to the local host. These are processed by the kernel, i.e., the
// iptables rules do no drop these packets.
ip_classifier[0] -> forward;
ip_classifier[1] -> Discard;

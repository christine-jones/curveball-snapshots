// $Id$
//
// This material is based upon work supported by the Defense Advanced
// Research Projects Agency under Contract No. N66001-11-C-4017.
// Copyright 2011 - Raytheon BBN Technologies - All Rights Reserved
//

require(package "curveball");

define($DEV eth0,
       $REVERSE_DEV eth1,
       $LOCAL_IP 10.0.0.1,
       $NUM_GENERATED 1,
       $PAUSE_INTERVAL 0,
       $INITIAL_PAUSE 10,
       $REVERSE true)

ip_classifier	:: IPClassifier(dst tcp port 443 or dst tcp port 80,
                                ip proto tcp and not dst host $LOCAL_IP, -)

rev_classifier	:: IPClassifier(src tcp port 443 or src tcp port 80,
                                ip proto tcp and not dst host $LOCAL_IP, -)

icmp_generator	:: ICMPGenerator(NUM_GENERATED $NUM_GENERATED,
                                 PAUSE_INTERVAL $PAUSE_INTERVAL,
                                 INITIAL_PAUSE $INITIAL_PAUSE,
                                 REVERSE $REVERSE)

icmp_error	:: ICMPError($LOCAL_IP, timeexceeded)

forward		:: Queue -> RawSocket(TCP)

dec_ttl		:: DecIPTTL
rev_ttl		:: DecIPTTL

// Set up iptables rule to drop all tcp packets forwarded on given interface
// such that the kernal and user-level click do not both process the packets.
CurveballKernelFilter(drop dev $DEV);

FromDevice($DEV, FORCE_IP true, METHOD LINUX) 
	-> Strip(14)
//	-> CheckIPHeader()
	-> dec_ttl
	-> ip_classifier;

FromDevice($REVERSE_DEV, FORCE_IP true, METHOD LINUX)
	-> Strip(14)
//	-> CheckIPHeader()
	-> rev_ttl
	-> rev_classifier;

ip_classifier[0]
//	-> CheckTCPHeader()
	-> icmp_generator
	-> forward;

rev_classifier[0]
//	-> CheckTCPHeader()
	-> icmp_generator
	-> forward;

icmp_generator[1]
	-> IPPrint() 
	-> icmp_error
	-> forward;

// Forward all non-TLS/HTTP TCP packets. Discard non-TCP packets and packets
// destined to the local host. These are processed by the kernel, i.e., the
// iptables rules do no drop these packets.
ip_classifier[1] -> forward;
ip_classifier[2] -> Discard;
rev_classifier[1] -> forward;
rev_classifier[2] -> Discard;


// The ICMP packet to notify the source of the ttl=0 is already generated
// by the kernel prior to this packet being handed to the click router.
// So nothing to do but drop the packet.

dec_ttl[1] -> Discard;
rev_ttl[1] -> Discard;

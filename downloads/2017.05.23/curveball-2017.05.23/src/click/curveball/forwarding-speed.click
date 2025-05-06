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

// Simply forwards all TCP/IP packets to user space to be forwarded
// by a python script.  The purpose is to determine the client->covert throughput.

define($DEV eth1)

classifier	:: Classifier(12/0800, -);
ip_classifier	:: IPClassifier(ip proto tcp, -)
user_land		:: ToUserDevice(0, TYPE stream, BURST 0, CAPACITY 64)
forward			:: ToHost()

FromDevice($DEV)
	-> classifier
	-> Strip(14)
	-> CheckIPHeader2()
	-> ip_classifier
	-> CheckTCPHeader()
	-> user_land;

classifier[1]  -> forward;			// Non-IP packet.
ip_classifier[1] -> Unstrip(14) -> forward;	// Non-TCP packet.

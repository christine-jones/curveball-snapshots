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

#ifndef CURVEBALL_BTSENTINELTEST_HH
#define CURVEBALL_BTSENTINELTEST_HH
#include <click/element.hh>
#include "sentineldetector.hh"
CLICK_DECLS


class BTSentinelTest : public Element {
  public:

    BTSentinelTest();
    ~BTSentinelTest();

    const char *class_name() const { return "BTSentinelTest"; }
    const char *port_count() const { return "0/0"; }
    const char *processing() const { return PUSH; }
    const char *flow_code()  const { return COMPLETE_FLOW; }
    int configure_phase() const { return CONFIGURE_PHASE_INFO; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

  private:

    BloomFilter		_bloom_filter;
    SentinelDetector *	_sentinel_detector;
};

CLICK_ENDDECLS
#endif

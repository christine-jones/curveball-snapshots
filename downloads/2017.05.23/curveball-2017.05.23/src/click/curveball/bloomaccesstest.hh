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

#ifndef CURVEBALL_BLOOMACCESSTEST_HH
#define CURVEBALL_BLOOMACCESSTEST_HH
#include <click/element.hh>
#include <click/string.hh>
#include "bloomfilter.hh"
CLICK_DECLS

//
// The initialize() method implements the entirety of the tests. When the
// element is instantiated the tests are automatically run.
//

#define NTRIALS 10000000

class BloomAccessTest : public Element { public:

    BloomAccessTest();
    ~BloomAccessTest();

    const char *class_name() const { return "BloomAccessTest"; }
    const char *port_count() const { return "0/0"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

  private:

    bool read_bloom_filter(void);

    char	_sentinels[NTRIALS][8];
    String 	_bloom_file;
    BloomFilter	_bloom_filter;

};

CLICK_ENDDECLS
#endif

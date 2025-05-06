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

#ifndef CURVEBALL_BLOOMFILTERTEST_HH
#define CURVEBALL_BLOOMFILTERTEST_HH
#include <click/element.hh>
CLICK_DECLS

// Element used for unit testing the BloomFilter class.
//
// The initialize() method implements the entirety of the tests. When the
// element is instantiated the tests are automatically run.
//
// See test/bloomfilter.testie.

class BloomFilterTest : public Element { public:

    BloomFilterTest();
    ~BloomFilterTest();

    const char *class_name() const { return "BloomFilterTest"; }

    int initialize(ErrorHandler *);

};

CLICK_ENDDECLS
#endif

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

#include <click/config.h>
#include "httpsentineltest.hh"
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS


HTTPSentinelTest::HTTPSentinelTest()
    : _sentinel_detector((SentinelDetector *)NULL)
{
}


HTTPSentinelTest::~HTTPSentinelTest()
{
}

int
HTTPSentinelTest::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "DETECTOR", 0, cpElement, &_sentinel_detector,
                        cpEnd);
}

int
HTTPSentinelTest::initialize(ErrorHandler *errh)
{
    if (!_sentinel_detector ||
        !_sentinel_detector->cast("SentinelDetector")) {
        errh->message("sentinel detector not configured");
        return  -1;
    }

    _sentinel_detector->update_sentinel_filter(&_bloom_filter);

    _bloom_filter = BloomFilter(8);
    _bloom_filter.insert("\x7b\x19\xaf\xe5\x98\x8d\x3c\xc4", 8);

    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPSentinelTest)

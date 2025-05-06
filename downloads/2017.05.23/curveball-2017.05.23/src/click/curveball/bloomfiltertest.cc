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
#include "bloomfiltertest.hh"
#include "bloomfilter.hh"
#include <click/error.hh>
#include <click/string.hh>
#include <click/vector.hh>
CLICK_DECLS


BloomFilterTest::BloomFilterTest()
{
}

BloomFilterTest::~BloomFilterTest()
{
}

int
BloomFilterTest::initialize(ErrorHandler *errh)
{
    // Invalid filters.
    BloomFilter invalid_filter1(0), invalid_filter2(31);

    // Test filter instantiation.
    BloomFilter empty_filter, filter1(30), filter2(5), filter3(18);

    errh->message("empty_filter: %d %0x %d",
                  empty_filter.hash_size(),
                  empty_filter.hash_mask(),
                  empty_filter.table_size());
    errh->message("filter1: %d %0x %d",
                  filter1.hash_size(),
                  filter1.hash_mask(),
                  filter1.table_size());
    errh->message("filter2: %d %0x %d",
                  filter2.hash_size(),
                  filter2.hash_mask(),
                  filter2.table_size());
    errh->message("filter3: %d %0x %d",
                  filter3.hash_size(),
                  filter3.hash_mask(),
                  filter3.table_size());

    // Test data insertion and membership.
    String data1("insert_this_data"),
           data2("invalid_data");

    filter1.insert(data1.data(), data1.length());
    errh->message("expecting true  ---> %d",
                  filter1.member(data1.data(), data1.length()));
    errh->message("expecting false ---> %d",
                  filter1.member(data2.data(), data2.length()));

    // Test the use of salt values.
    Vector<uint32_t> salts;
    salts.push_back(1);
    salts.push_back(2);
    salts.push_back(3);
    salts.push_back(4);
    salts.push_back(5);

    BloomFilter salt_filter(7, salts);
    salt_filter.insert(data1.data(), data1.length());
    errh->message("expecting true  ---> %d",
                  salt_filter.member(data1.data(), data1.length()));
    errh->message("expecting false ---> %d",
                  salt_filter.member(data2.data(), data2.length()));
    errh->message("All tests passed!");

    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(BloomFilterTest)

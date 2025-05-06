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
#include "bloomfilter.hh"
#include "smoosh1_hash.hh"
CLICK_DECLS


// Avoid using math library.
static int
pow(int x, int y)
{
    int rval = 1;
    for (int i = 0; i < y; ++i) {
        rval *= x;
    }
    return rval;
}

BloomFilter::BloomFilter():
    _hash_size(0), _hash_mask(0xFFFFFFFF), _print_uninit_mesg(true)
{
}

BloomFilter::BloomFilter(int hash_size):
    _hash_size(hash_size), _print_uninit_mesg(true)
{
    initialize();
}

BloomFilter::BloomFilter(int hash_size, const Bitvector& bit_table):
    _hash_size(hash_size), _bit_table(bit_table), _print_uninit_mesg(true)
{
    initialize(false);
}

BloomFilter::BloomFilter(int hash_size, const Vector<uint32_t>& salt_values):
    _hash_size(hash_size), _salt_values(salt_values), _print_uninit_mesg(true)
{
    initialize();
}

BloomFilter::BloomFilter(int hash_size, const Bitvector& bit_table,
                         const Vector<uint32_t>& salt_values):
    _hash_size(hash_size), _salt_values(salt_values), _bit_table(bit_table),
    _print_uninit_mesg(true)
{
    initialize(false);
}

BloomFilter::~BloomFilter()
{
}

int
BloomFilter::bit_vector_size(int hash_size)
{
    return ((hash_size <= 0)? 0 : pow(2, hash_size));
}

void
BloomFilter::initialize(bool create_table)
{
    if (_hash_size <= 0 || _hash_size > 30) {
        click_chatter("BloomFilter::initialize: invalid hash size %d",
                      _hash_size);
        _hash_size = 0;
        _hash_mask = 0xFFFFFFFF;
        _bit_table.resize(0);
        return;
    }

    _hash_mask = 0xFFFFFFFF >> (32 - _hash_size);

    if (create_table) {
        _bit_table.resize(bit_vector_size(_hash_size));
    }

    if (_bit_table.size() < bit_vector_size(_hash_size)) {
        click_chatter("BloomFilter::initialize: invalid table size: %d %d",
                      _hash_size, _bit_table.size());
        _hash_size = 0;
        _hash_mask = 0xFFFFFFFF;
        _bit_table.resize(0);
        return;
    }
}

void
BloomFilter::insert(const char *data, int len)
{
    if (_hash_size == 0) {
        click_chatter("BloomFilter::insert: uninitialized hash table");
        return;
    }

    if (_salt_values.empty()) {
        _bit_table[smoosh1_hash(data, len, len) & _hash_mask] = true;

    } else {
        for (Vector<uint32_t>::iterator salt = _salt_values.begin();
             salt != _salt_values.end();
             ++salt) {
            _bit_table[smoosh1_hash(data, len, *salt) & _hash_mask] = true;
        }
    }
}

void
BloomFilter::insert(int bit)
{
    if (bit >= 0 && bit < bit_vector_size(_hash_size)) {
        _bit_table[bit] = true;
    }
}

bool
BloomFilter::member(const char *data, int len)
{
    if (_hash_size == 0) {
        if (_print_uninit_mesg) {
            click_chatter("BloomFilter::member: uninitialized hash table");
            _print_uninit_mesg = false;
        }
        return false;
    }

    if (_salt_values.empty()) {
        return _bit_table[smoosh1_hash(data, len, len) & _hash_mask];

    } else {
        for (Vector<uint32_t>::const_iterator salt = _salt_values.begin();
             salt != _salt_values.end();
             ++salt) {
            if (!_bit_table[smoosh1_hash(data, len, *salt) & _hash_mask]) {
                return false;
            }
        }
    }

    return true;
}

bool
BloomFilter::member(int bit) const
{
    if (bit >= 0 && bit < bit_vector_size(_hash_size)) {
        return _bit_table[bit];
    }

    return false;
}

BloomFilter &
BloomFilter::operator=(const BloomFilter &x)
{
    if (&x != this) {
        _hash_size = x._hash_size;
        _hash_mask = x._hash_mask;
        _salt_values = x._salt_values;
        _bit_table = x._bit_table;
    }
    return *this;
}


CLICK_ENDDECLS
ELEMENT_PROVIDES(BloomFilter)

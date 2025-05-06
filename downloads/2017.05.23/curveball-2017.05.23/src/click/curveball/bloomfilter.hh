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

#ifndef CURVEBALL_BLOOMFILTER_HH
#define CURVEBALL_BLOOMFILTER_HH
#include <click/bitvector.hh>
#include <click/vector.hh>
CLICK_DECLS

// Class that implements a Bloom filter.
//
// A Bloom filter uses a set of hash functions to map a set of elements
// into a bit array. An x-bit hash requires a 2^x-sized bit array in which
// each hash value maps to a single array position.
//
// The Bloom filter array is initialized to all zeros. An element is
// inserted into the Bloom filter by computing the set of hashes.
// Each corresponding bit position within the array is marked to one.
// Subsequently, an element's membership in the filter can be determined
// by computing the set of hashes and checking the inidicated bit
// positions. If any of the bits are zero, then the element is not
// a member of that Bloom filter; otherwise, if all bits are marked
// as one, then it is highly likely that the element is a member.
// However, it is possible that some other set of insertions caused
// all the bit positions to be set, creating a false positive.
//
// A single hash function is used to simulate multiple hash functions
// with the use of "salt" values. The hash function is initialized with
// a different salt value for each distinct hash required. This Bloom
// filter class may be instantiated with any number of 32-bit salt values.
// If no salt values are provided, then a single hash is computed for
// each inserted element.
//
// The underlying bit array is an instance of the Bitvector class provided
// by Click. However, the use of Click's built-in Bitvector class limits
// the size of the Bloom filter to 2^30 bits. If larger Bloom filters are
// required, then a new bit array class will need to be implemented.
//
// This Bloom filter implemenation uses a single hash function (currently
// smoosh1, with different seeds) for insertion and membership tests. It
// may be useful in the future to support a set of hash functions. The
// DR2DP protocol would need to be updated such that messages containing
// new Bloom filters for upload specify the hash function to use. This
// would also require that the DR send a notification of which hash
// functions are supported.

class BloomFilter { public:

    // Empty, uninitialized Bloom filter.
    BloomFilter();

    // Empty Bloom filter with a given hash size.
    BloomFilter(int hash_size);

    // Already constructed Bloom filter with a given hash size.
    BloomFilter(int hash_size, const Bitvector &bit_table);

    // Empty Bloom filter with a given hash size and set of salt values.
    BloomFilter(int hash_size, const Vector<uint32_t>& salt_values);

    // Already constructed Bloom filter with a given hash size and
    // set of salt values.
    BloomFilter(int hash_size, const Bitvector &bit_table,
                const Vector<uint32_t>& salt_values);

    ~BloomFilter();

    // Calculate the bit size of a Bloom filter given a hash size.
    static int bit_vector_size(int hash_size);

    // Insert an element into the Bloom filter.
    void insert(const char *data, int len);

    // Determine if an element is a member of the Bloom filter.
    bool member(const char *data, int len);

    // Set this Bloom filter to be a copy of the given Bloom filter.
    BloomFilter &operator=(const BloomFilter &x);

    // Data accessors.
    int                      hash_size()   const { return _hash_size; }
    uint32_t                 hash_mask()   const { return _hash_mask; }
    int	                     table_size()  const { return _bit_table.size(); }
    const Vector<uint32_t> & salt_values() const { return _salt_values; }

    // Bit insert/memberhip methods used for testing and debugging.
    void insert(int bit);
    bool member(int bit) const;

  private:

    // Common class initialization used by all constructors.
    // If the 'create_table' parameter is 'true', then a bit array is created;
    // otherwise, it is assumed that the bit array has already been constructed.
    void initialize(bool create_table = true);

    // Size of hash used to index into the bit array. (0 < _hash_size < 31)
    int			_hash_size;

    // Mask used to produce hash of given size from a 32-bit value.
    uint32_t		_hash_mask;

    Vector<uint32_t>	_salt_values;

    // Bit array of size 2^_hash_size bits.
    Bitvector		_bit_table;

    bool		_print_uninit_mesg;
};

CLICK_ENDDECLS
#endif

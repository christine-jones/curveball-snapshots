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

#ifndef TEST_MAIN
#include <click/config.h>
#include <click/glue.hh>
CLICK_DECLS
#else /* Not TEST_MAIN */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#endif /* TEST_MAIN */

#include "smoosh1_hash.hh"

uint32_t
smoosh1_hash(const char *key, uint32_t value_len, uint32_t seed)
{
    unsigned const char *value = (unsigned const char *)key;
    uint64_t curr_seed = seed;
    uint64_t temp = 0;
    uint32_t i;
    uint32_t j;
    uint32_t chunks = value_len / 4;

    /*
     * We want the length to have a notable effect on the outcome;
     * some hash functions see a lot of collisions with prefixes.
     *
     * These constants were picked pseudo-randomly and there might
     * be better numbers.
     */

    temp = ((uint64_t) value_len) * 0x18521031531;
    temp ^= 0x1e2093c89a0b;
    temp ^= ((uint64_t) seed) * 0x13467;

    /*
     * For each byte, xor it with a small constant, then
     * multiply it by a large constant to smoosh it.  Then
     * xor the values together, and add them to the curr_seed
     * (and do some shifts on curr_seed to mix the bits).
     * Finally xor the curr_seed with temp.
     *
     * Note that curr_seed is not reinitialized, but keeps
     * accumulating as the loop iterates.
     *
     * The reason for the first xor (i.e. 0x11 ^ value[0])
     * in the sequence is to deal with values that contain
     * long strings of zero bytes, which apparently are not
     * unusual.  If the bytes are all zero, then the multiply
     * to smoosh the bytes will give a zero, and this ruins
     * the hash.  This is a cheap trick because if the string
     * has long sequences that match up with the arbitrary
     * constants I've chosen, the effect is exactly the same.
     *
     * NOTE: if you are certain that you don't need to worry
     * about a lot of zero bytes appearing in the input,
     * you can remove the initial xor with the byte.  This
     * makes the hash MUCH faster (and faster than its
     * contemporaries) at the cost of failing for this case.
     *
     * The multiplications with different constants effectively
     * shifts each byte to multiple offsets; using different
     * constants for the different bytes means that different
     * bits from the original bytes "interact" with each other
     * in the xor.  This substantially improves diffusion.
     *
     * The shift at the end breaks the symmetry and means that
     * repeated patterns in the input don't completely
     * cancel each other out and ensures that order matter
     * ("aaaabbbb" won't hash to the same value as "bbbbaaaa").
     */

    for (i = 0; i < chunks; i ++) {
	uint32_t offset = i << 2;
	uint64_t c0 = 0x11 ^ value[offset + 0];
	uint64_t c1 = 0x22 ^ value[offset + 1];
	uint64_t c2 = 0x44 ^ value[offset + 2];
	uint64_t c3 = 0x88 ^ value[offset + 3];

	c0 *= 0x00030509;
	c1 *= 0x09000301;
	c2 *= 0x05090003;
	c3 *= 0x03010900;

	curr_seed += c0 ^ c1 ^ c2 ^ c3;
	curr_seed += curr_seed << 3;

	temp ^= curr_seed;
    }

    /*
     * Deal with any leftover bytes
     *
     * This method is adequate for the things I'm hashing against, but
     * it isn't as strong as the main loop and could be improved.
     *
     * It would be better to unroll the main loop here, but this has
     * to be done with more care than is immediately obvious.
     */
    for (j = 0; (i << 2) + j < value_len; j++) {
	uint64_t c = value[(i << 2) + j];

	c ^= (0x11 << j);
	c *= 0x03050901 << (j * 2);

	curr_seed += c;
	curr_seed += curr_seed << 3;

	temp ^= curr_seed;
    }

    /*
     * Provoke avalanching by folding the bits over at different offsets
     *
     * These offsets were chosen by a combination of randomness and
     * trial and error: trying to keep them small enough so we don't
     * just shift info off into oblivion, but large enough so that
     * most bits have an opportunity to "interact" with the other bits.
     *
     * Someone with a better understanding of the theory might find
     * better constants (or fewer of them).
     */

    temp ^= (temp << 16);
    temp += (temp >> 3);
    temp ^= (temp << 8);
    temp += (temp >> 6);
    temp ^= (temp << 4);
    temp += (temp >> 12);
    temp ^= (temp << 2);
    temp += (temp >> 11);
    temp ^= (temp << 1);

    /*
     * Even though we've been keeping 64 bits of state in temp,
     * only the bottom 32 bits are "good".  Don't try to use this
     * as a 64-bit hash...
     */
    return temp;
}

#ifndef TEST_MAIN
CLICK_ENDDECLS
ELEMENT_PROVIDES(SMOOSH1HASH)
#else /* Not TEST_MAIN */

/*
 * Create a bunch of random strings of different lengths (all short),
 * hash them with different seeds, and print out the results.
 *
 * The output of this program is meant to be used as the input for
 * smoosh1_hash.py.  This will provide confidence that both implementations
 * match.
 */

int
main(int argc, char **argv)
{
    unsigned int i;
    unsigned char buf[100];
    uint32_t len, c, seed;

    for (len = 1; len < 25; len++) {
	for (i = 0; i < 100; i++) {
	    for (c = 0; c < len; c++) {
		buf[c] = rand();
	    }

	    /* don't try every seed; just a few */
	    for (seed = 0; seed < 5000; seed += seed + 1) {

		printf("X %.8x ", smoosh1_hash((const char *)buf,
			    len, seed));
		for (c = 0; c < len; c++) {
		    printf("%.2x", 0xff & buf[c]);
		}
		printf(" %.8x\n", seed);
	    }
	}
    }

    return 0;
}

#endif /* TEST_MAIN */

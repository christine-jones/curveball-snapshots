#ifndef CB_STENCIL_H
#define CB_STENCIL_H 1

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
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#define CB_BITS_PER_BYTE 8 /* TODO -- should come from bits.h */

/*
 * CB_STENCIL_BLKSIZE_NBYTES is the number of bytes per cipher block, and
 * CB_STENCIL_NBITS is the number of bits we need to represent in the stencil.
 *
 * The value of CB_STENCIL_BYTES_PER_CIPHER_BLK = 16 is chosen for convenience
 * with AES.
 *
 * The value of CB_STENCIL_NBITS = ((2 + 32) * CB_BITS_PER_BYTE) is chosen to
 * match the size of the ciphersuite identifier (the two bytes) and the size
 * of the ServerRandom payload from SSL/TLS (the next 32).
 *
 * CB_STENCIL_NBITS_PER_BLK is the number of bits we encode inside each cipher
 * block.  Note that we assume that the stencils always encoded the same, fixed
 * number of bits per fixed-size cipher block.  (We currently choose to always
 * encode 8 bits of the data within each 16-byte stencil block.)
 *
 * Note that even if we're not using a block cipher, we pretend (for the
 * purpose of the stencil encoding) that we are.  If the number of bits we try
 * to encode in each block is greater than the number of bytes per block, then
 * some of the assumptions below will break.
 */

#define CB_STENCIL_BLKSIZE_NBYTES	(16)
#define CB_STENCIL_NBITS		((2 + 32) * BITS_PER_BYTE)
#define CB_STENCIL_NBITS_PER_BLK	(8)

/*
 * Compute constants in terms of bytes and bits.
 *
 * TODO: the math here assumes that all the sizes are all multiples of 8,
 * so we don't have to round up the number of bytes.  This is lame.
 */

#define CB_STENCIL_NBYTES	(CB_STENCIL_NBITS / CB_BITS_PER_BYTE)

#define CB_STENCIL_BLKSIZE_NBITS	\
    (CB_STENCIL_BLKSIZE_NBYTES * CB_BITS_PER_BYTE)

#define CB_STENCIL_MASK_NBYTES		\
    ((CB_STENCIL_BLKSIZE_NBYTES * CB_STENCIL_NBITS) / CB_STENCIL_NBITS_PER_BLK)
#define CB_STENCIL_MASK_NBITS		\
    (CB_STENCIL_MASK_NBYTES * CB_BITS_PER_BYTE)

/*
 * Represents the data that will be encoded by a stencil.
 */
typedef struct {
    unsigned char bytes[CB_STENCIL_NBYTES];
} cb_stencil_data_t;

/*
 * Represents a stencil-encoded cb_stencil_data_t.  Since only a fraction
 * of the bits in the encoding correspond to the stencil data, this is
 * much larger than a cb_stencil_data_t.
 */
typedef struct {
    unsigned char bytes[CB_STENCIL_MASK_NBYTES];
} cb_stencil_enc_t;

/*
 * A stencil spec is an array of all of the offsets of the stencil bits, and
 * the values of those bits.
 *
 * NOTE: Some parts of the code assume that the offsets are monotonically
 * increasing.
 *
 * Depending on context, the values might or might not have any significance.
 */
typedef struct {
    unsigned int n_offsets; /* 0 <= CB_STENCIL_NBITS */
    unsigned int offsets[CB_STENCIL_NBITS];
    unsigned char values[CB_STENCIL_NBITS];
} cb_stencil_spec_t;

extern cb_stencil_enc_t *cb_stencil_mask(cb_stencil_spec_t *spec);

extern unsigned int cb_stencil_check(cb_stencil_enc_t *data,
	cb_stencil_spec_t *spec);

extern cb_stencil_spec_t *cb_stencil_spec_default(cb_stencil_data_t *data);

extern int cb_stencil_read(cb_stencil_spec_t *spec, cb_stencil_enc_t *enc,
	cb_stencil_data_t *data);

extern int cb_stencil_encrypt_sr(const unsigned char *sr,
	unsigned char *enc_sr,
	const unsigned char *enc_key, unsigned int enc_keysize);

extern int cb_stencil_aes_create_plaintext(const unsigned char *sr,
	cb_stencil_enc_t *plaintext,
	unsigned char *plaintext_prefix,
	const unsigned char *tls_key, unsigned int tls_keysize,
	const unsigned char *tls_iv,
	const unsigned char *enc_key, unsigned int enc_keysize);

extern int cb_stencil_send(PRFileDesc *ssl,
	unsigned char *full_sentinel,
	const unsigned char *enc_key, unsigned int enc_keysize,
	const unsigned char *suffix);

#endif /* CB_STENCIL_H */

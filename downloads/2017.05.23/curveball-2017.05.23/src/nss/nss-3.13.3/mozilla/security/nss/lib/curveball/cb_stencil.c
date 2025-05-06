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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prerror.h"
#include "prio.h"
#include "nss.h"

#include "blapit.h"
#include "blapi.h"

#include "../freebl/rijndael.h"
#include "pk11pub.h"
#include "ssl.h"
#include "sslproto.h"
#include "sslimpl.h"

#include "cb_stencil.h"
#include "curveball_rijndael.h"
#include "curveball_ssl.h"

/**
 * Allocate a new cb_stencil_enc_t structure.
 */
static cb_stencil_enc_t *
cb_stencil_alloc(void)
{
    return calloc(sizeof (cb_stencil_enc_t), 1);
}

/**
 * Clear a cb_stencil_enc_t structure
 */
static cb_stencil_enc_t *
cb_stencil_clear(cb_stencil_enc_t *enc)
{

    memset(enc->bytes, 0, CB_STENCIL_MASK_NBYTES);
    return enc;
}

/**
 * Set the bit at the given ind in the array of bytes to the given value
 */
static int
cb_stencil_set_bit(unsigned char *bytes, unsigned int ind, int value)
{
    unsigned int byte_offset = ind / CB_BITS_PER_BYTE;
    unsigned int bit_offset = ind % CB_BITS_PER_BYTE;

    if (ind >= CB_STENCIL_MASK_NBITS) {
	return -1;
    }

    if (value) {
	bytes[byte_offset] |= 1 << bit_offset;
    }
    else {
	bytes[byte_offset] &= ~(1 << bit_offset);
    }

    return ind;
}

/**
 * Get the bit at the given ind in the array of bytes
 */
static int
cb_stencil_get_bit(unsigned char *bytes, unsigned int ind)
{
    unsigned int byte_offset = ind / CB_BITS_PER_BYTE;
    unsigned int bit_offset = ind % CB_BITS_PER_BYTE;

    if (ind >= CB_STENCIL_MASK_NBITS) {
	return -1;
    }

    return (bytes[byte_offset] & (1 << bit_offset)) ? 1 : 0;
}

/**
 * Given a stencil spec, create and return a corresponding stencil enc for it.
 *
 * Does not gripe if the spec is bogus.
 */
cb_stencil_enc_t *
cb_stencil_mask(cb_stencil_spec_t *spec)
{
    unsigned int i;
    cb_stencil_enc_t *mask = cb_stencil_alloc();

    /* TODO: we don't check that the offsets are unique.  We could
     * end up with a mask with fewer than spec->n_offsets bits set,
     * if there are duplicate offsets
     */
    for (i = 0; i < spec->n_offsets && i < CB_STENCIL_NBITS; i++) {
	unsigned int offset = spec->offsets[i];

	if (offset >= CB_STENCIL_MASK_NBITS) {
	    /* TODO: gripe -- the offset is invalid: too high */
	    continue;
	}

	if (cb_stencil_get_bit(mask->bytes, offset)) {
	    /* TODO: gripe -- we've already set this bit */
	    continue;
	}

	cb_stencil_set_bit(mask->bytes, offset, 1);
    }

    return mask;
}

/**
 * Check whether the given data matches the given prefix of the spec.
 * Returns 0 if not, non-zero if so.
 *
 * Start checking at base_offset in the spec's offset array, and
 * continue for n_offset elements.  If n_offset is -1, then continue
 * to the end.  (To check the complete spec, use base_offset=0 and
 * n_offset=-1.)
 */
static unsigned int
cb_stencil_check_partial(cb_stencil_enc_t *data, cb_stencil_spec_t *spec,
	unsigned int base_offset, unsigned int n_offset)
{
    unsigned int i;
    unsigned int end_offset;

    if (n_offset < 0) {
	n_offset = CB_STENCIL_NBITS - base_offset;
    }

    end_offset = base_offset + n_offset;

    for (i = base_offset; (i < spec->n_offsets) && (i < end_offset); i++) {
	unsigned int offset = spec->offsets[i];
	unsigned int val = spec->values[i] ? 1 : 0;

	if (offset >= CB_STENCIL_MASK_NBITS) {
	    /* TODO: gripe: the offset is invalid: too high */
	    continue;
	}

	if (cb_stencil_get_bit(data->bytes, offset) != val) {
	    /* TODO: diagnostic about where the error happened */
	    /*
	    printf("failed at offset %u i %u wanted %u got %u\n",
		    offset, i, val,
		    cb_stencil_get_bit(data->bytes, offset));
	    */
	    return 0;
	}
    }

    return 1;
}

/**
 * Check whether the given data matches the spec.
 * Returns 0 if not, non-zero if so.
 *
 * Start checking at base_offset in the spec's offset array, and
 * continue for n_offset elements.  If n_offset is -1, then continue
 * to the end.  (To check the complete spec, use base_offset=0 and
 * n_offset=-1.)
 */
unsigned int
cb_stencil_check(cb_stencil_enc_t *data, cb_stencil_spec_t *spec)
{
    return cb_stencil_check_partial(data, spec, 0, -1);
}

/**
 * Create and return an instance of default stencil spec.  If data is
 * non-NULL, then initialize the data mask with it; otherwise leave
 * the data uninitialized.
 *
 * The default stencil, for N bits per stencil, is just the low-order
 * bit of each byte for the last N byes in each block.  For example,
 * for 8 bits per block it would be 0x00000000000000000101010101010101.
 *
 * This method fails when N is greater than the number of bytes per
 * block, but that's OK because it's impractical to approach this 
 * limit for reasonably-sized blocks.
 *
 * TODO: remove the assumption that the number bits per block divides
 * the number of blocks.
 */
cb_stencil_spec_t *
cb_stencil_spec_default(cb_stencil_data_t *data)
{
    cb_stencil_spec_t *spec = calloc(sizeof(cb_stencil_spec_t), 1);
    unsigned int n_blks = CB_STENCIL_NBITS / CB_STENCIL_NBITS_PER_BLK;
    unsigned int offset_ind = 0;
    unsigned int blk;
    unsigned int i;
    unsigned int first_offset_in_blk;

    /* The first offset to use within each blk */
    first_offset_in_blk = CB_BITS_PER_BYTE *
	    (CB_STENCIL_BLKSIZE_NBYTES - CB_STENCIL_NBITS_PER_BLK);

    for (blk = 0; blk < n_blks; blk++) {
	for (i = 0; i < CB_STENCIL_NBITS_PER_BLK; i++) {
	    spec->offsets[offset_ind++] = first_offset_in_blk +
		    (blk * CB_STENCIL_BLKSIZE_NBITS) + (i * CB_BITS_PER_BYTE);
	}
    }
    spec->n_offsets = offset_ind; /* usually CB_STENCIL_NBITS */

    if (data != NULL) {
	for (i = 0; i < CB_STENCIL_NBITS; i++) {
	    spec->values[i] = cb_stencil_get_bit(data->bytes, i);
	}
    }

    return spec;
}

/**
 * Read the data encoded by enc, according to the spec, and place
 * the result in data
 *
 * Assumes that the cb_stencil_data_t is allocated with enough space
 * to hold the data.
 */
int
cb_stencil_read(cb_stencil_spec_t *spec, cb_stencil_enc_t *enc,
	cb_stencil_data_t *data)
{
    unsigned int i;

    memset(data->bytes, 0, CB_STENCIL_NBYTES);

    for (i = 0; i < spec->n_offsets; i++) {
	unsigned int offset = spec->offsets[i];
	unsigned char bit = cb_stencil_get_bit(enc->bytes, offset);

	cb_stencil_set_bit(data->bytes, i, bit);
    }

    return 0;
}

/*
 * Encrypt the sr, using the given enc_key (with length enc_keysize), and
 * place the result in the buffer located at enc_sr.  sr and enc_sr are
 * assumed to be CB_STENCIL_NBYTES in length.  The sr and enc_sr can point
 * to the same buffer: this function can work on the data in-place.
 *
 * The sr is xor'd with an expansion of the key, which must be of reasonable
 * length, known only to the client and DP, and never reused.  (the intent
 * is to use some or all of the sentinel label, which is a nonce known to
 * both)   See nstencil.py for a description of the general expansion.
 *
 * NOTE: This routine assumes that CB_STENCIL_NBYTES is no more than 64.
 * It doesn't allocate enough memory to tolerate anything larger right now.
 *
 * Returns 0 if successful, -1 if failed for any reason.
 */
int
cb_stencil_encrypt_sr(const unsigned char *sr, unsigned char *enc_sr,
	const unsigned char *enc_key, unsigned int enc_keysize)
{
    unsigned char prf[64]; /* large enough for a SHA512 */
    unsigned int i;

    if (CB_STENCIL_NBYTES > 64) {
	fprintf(stderr, "cb_stencil_encrypt_sr: NBYTES too large\n");
	return -1;
    }

    if (sr == NULL) {
	fprintf(stderr, "cb_stencil_encrypt_sr: sr is NULL\n");
	return -1;
    }

    if (enc_sr == NULL) {
	fprintf(stderr, "cb_stencil_encrypt_sr: enc_sr is NULL\n");
	return -1;
    }

    if (enc_key == NULL) {
	fprintf(stderr, "cb_stencil_encrypt_sr: no key provided\n");
	return -1;
    }

    /* a key of less than 16 bytes is weak; less than 8 bytes silly */
    if (enc_keysize < 8) {
	fprintf(stderr, "cb_stencil_encrypt_sr: key too small\n");
	return -1;
    }

    /* the first 512 bits of the PRF */
    SHA512_HashBuf(prf, enc_key, enc_keysize);

    if (0) { /* DIAGNOSTIC */
	printf("prf: %d\n", CB_STENCIL_NBYTES);
	for (i = 0; i < CB_STENCIL_NBYTES; i++) {
	    printf("%.2x", prf[i]);
	}
	printf("\n");
    }

    /* xor the sr with the first NBYTES of the PRF */
    for (i = 0; i < CB_STENCIL_NBYTES; i++) {
	enc_sr[i] = prf[i] ^ sr[i];
    }

    if (0) { /* DIAGNOSTIC */
	printf("encrypted sr: \n", CB_STENCIL_NBYTES);
	for (i = 0; i < CB_STENCIL_NBYTES; i++) {
	    printf("%.2x", enc_sr[i]);
	}
	printf("\n");
    }

    return 0;
}

/**
 * Given data to stencil, initialize the plaintext hex string
 * such that when the plaintext is encrypted, the value of the stencil
 * bits encodes the data for the default stencil spec.
 *
 * This function is hard-wired to use AES in CBC mode, starting
 * with the given iv.
 *
 * Note that we assume here (again) that the offsets lists in the spec
 * are listed in increasing numerical order, so that the offsets in
 * the first block are first, followed by the offsets in the second
 * block, and so forth.  This is essential because only check the
 * corresponding prefix of the spec during each iteration.
 *
 * If enc_key is non-NULL, then the combination of the ciphersuite
 * identifier and the ServerRandom are encrypted with enc_key before
 * the plaintext is created.  If enc_key is NULL, neither are encrypted.
 *
 * TODO: enc_key shouldn't be optional.  It is completely insecure to
 * create a stencil encoding of the plaintext of the ServerRandom.
 */
int
cb_stencil_aes_create_plaintext(const unsigned char *sr,
	cb_stencil_enc_t *plaintext,
	unsigned char *plaintext_prefix,
	const unsigned char *tls_key, unsigned int tls_keysize,
	const unsigned char *tls_iv,
	const unsigned char *enc_key, unsigned int enc_keysize)
{
    cb_stencil_spec_t *spec = NULL;
    unsigned int blkno;
    unsigned int blks = CB_STENCIL_NBITS / CB_STENCIL_NBITS_PER_BLK;
			    /* TODO: should be based on bits per blk */
    unsigned int max_attempts = 2048;	/* TODO potentially TOO SMALL */
    unsigned int tot_attempts = 0;
    cb_stencil_enc_t ciphertext;
    unsigned int plaintext_prefix_len;
    unsigned int out_len;
    cb_stencil_data_t data;

    AESContext _enc_context;
    AESContext *enc_context = &_enc_context;

    AES_InitContext(enc_context, tls_key, tls_keysize, tls_iv,
	    NSS_AES_CBC, 1, 16);

    /*
     * The first byte of the data is the low 8 bits of the ciphersuite,
     * and the second byte is bits 8..15 of the ciphersuite.
     *
     * This is a hack: we infer the ciphersuite from the keysize.
     * This only works because we only support two AES ciphersuites
     * right now, and we can tell which is which from the keysize.
     */
    if (tls_keysize == 16) {
	data.bytes[0] = TLS_RSA_WITH_AES_128_CBC_SHA & 0xff;
	data.bytes[1] = (TLS_RSA_WITH_AES_128_CBC_SHA >> 8) & 0xff;
    }
    else if (tls_keysize == 32) {
	data.bytes[0] = TLS_RSA_WITH_AES_256_CBC_SHA & 0xff;
	data.bytes[1] = (TLS_RSA_WITH_AES_256_CBC_SHA >> 8) & 0xff;
    }
    else {
	/* TODO: set an error code */
	return -1;
    }

    memmove(data.bytes + 2, sr, CB_STENCIL_NBYTES - 2);

    if (enc_key != NULL) {

	if (0) { /* DIAGNOSTIC */
	    unsigned int j;

	    printf("UNENCRYPTED stencil val:\n");
	    for (j = 0; j < CB_STENCIL_NBYTES; j++) {
		printf("%.2x", data.bytes[j]);
	    }
	    printf("\n");
	    fflush(stdout);
	}

	cb_stencil_encrypt_sr(data.bytes, data.bytes, enc_key, enc_keysize);

	if (0) { /* DIAGNOSTIC */
	    unsigned int j;

	    printf("ENCRYPTED stencil val:\n");
	    for (j = 0; j < CB_STENCIL_NBYTES; j++) {
		printf("%.2x", data.bytes[j]);
	    }
	    printf("\n");
	    fflush(stdout);
	}
    }

    spec = cb_stencil_spec_default(&data);

    if (plaintext_prefix != NULL) {
	plaintext_prefix_len = strlen((const char *) plaintext_prefix);
    }

    memset(plaintext->bytes, 0, CB_STENCIL_MASK_NBYTES);

    for (blkno = 0; blkno < blks; blkno++) {
	unsigned int enc_len = (1 + blkno) * CB_STENCIL_BLKSIZE_NBYTES;
	unsigned int attempt;

	/* printf("starting blkno %u\n", blkno); */

	for (attempt = 0; attempt < max_attempts; attempt++) {
	    tot_attempts++;

	    /*
	     * Basic approach:
	     *
	     * 1. create a new block, append to plaintext
	     * 2. encrypt the new block
	     * 3. test to see whether the encryption of the new block
	     *    encodes the data according to the given stencil spec
	     * 3a) if so, break out of this loop
	     * 3b) if no, back out the change and repeat.
	     *
	     * It would be more efficient if we only encrypted the
	     * new block, instead of encrypting everything in the
	     * entire candidate plaintext, but this requires more
	     * careful management of the iv, so we don't do that yet.
	     */

	    /* Create a new block, and add to the end of the plaintext.
	     * This is a placeholder.  It works but is slooow.
	     *
	     *
	     * Pick random values and express them as hex.
	     * TODO: This is not strongly random.
	     * TODO: This makes assumptions about the length of a blk.
	     */
	    {
		char new_blk[CB_STENCIL_BLKSIZE_NBYTES + 1];
		unsigned int rs[4];
		unsigned int r0, r1, r2, r3;

		PK11_GenerateRandom((unsigned char *) rs,
			4 * sizeof(unsigned int));

		r0 = (unsigned int) rs[0] & 0xffffffff;
		r1 = (unsigned int) rs[1] & 0xffffffff;
		r2 = (unsigned int) rs[2] & 0xffffffff;
		r3 = (unsigned int) rs[3] & 0xffffffff;

		PR_snprintf(new_blk, CB_STENCIL_BLKSIZE_NBYTES + 1,
			"%.8x%.8x%.8x%.8x", r0, r1, r2, r3);
		memcpy(plaintext->bytes + (CB_STENCIL_BLKSIZE_NBYTES * blkno),
			new_blk, CB_STENCIL_BLKSIZE_NBYTES);

		/*
		printf("PLAINTEXT ADDITION %u %u %s\n",
			blkno, attempt, new_blk);
		*/
	    }

	    /*
	     * If the blkno is zero, and there's a plaintext_prefix,
	     * then copy it verbatim into the first block, overwriting
	     * the randomness.
	     */
	    if ((blkno == 0) && (plaintext_prefix != NULL)) {
		memmove(plaintext->bytes, plaintext_prefix,
			plaintext_prefix_len);
	    }

	    /* Encrypt the resulting plaintext */
	    /*
	     * TODO: we encrypt everything, not just the new blk.
	     * This is because I haven't yet figured out how to roll
	     * back only part of the IV state.
	     */
	    AES_Encrypt(enc_context, ciphertext.bytes, &out_len, enc_len,
		    plaintext->bytes, enc_len);

	    /*
	    printf("Test Cipher: ");
	    for (j = 0; j < enc_len; j++) {
		printf("%.2x", ciphertext.bytes[j]);
	    }
	    printf("\n");
	    */

	    if (cb_stencil_check_partial(&ciphertext, spec,
		    blkno * CB_STENCIL_NBITS_PER_BLK,
		    CB_STENCIL_NBITS_PER_BLK)) {
		/* printf("success blk %u attempt %u\n", blkno, attempt); */
		break;
	    }
	    else {
		/* Rewind the crypto state */
		/* TODO: this is lame: we don't roll back part of
		 * the state, but instead roll back everything to
		 * the beginning.  It would be much better if we only
		 * had to test-encrypt the most recent block.
		 */

		/* PK11_DestroyContext(enc_context, PR_TRUE); */

		AES_InitContext(enc_context, tls_key, tls_keysize, tls_iv,
			NSS_AES_CBC, 1, 16);
	    }

	}

	/* Give up if we've made too many unsuccessful attempts */
	if (attempt == max_attempts) {
	    /* printf("failed -- too many attempts\n"); */
	    return -1;
	}
    }

    /* For the sake of debugging, print out the result */
    /* TODO: make this conditional */
    if (0) { /* DIAGNOSTIC */
	int j;
	int len = blkno * CB_STENCIL_BLKSIZE_NBYTES;

	printf("len = %d\n", len);
	printf("Cipher (hex): ");
	for (j = 0; j < len; j++) {
	    printf("%.2x", ciphertext.bytes[j]);
	}
	printf("\n");

	printf("Plain (text): ");
	for (j = 0; j < len; j++) {
	    printf("%c", plaintext->bytes[j]);
	}
	printf("\n");

	printf("Success after %u attempts %u blks\n", tot_attempts, blkno);
    }

    return 0;
}

int
cb_stencil_send(PRFileDesc *ssl,
	unsigned char *full_sentinel,
	const unsigned char *enc_key, unsigned int enc_keysize,
	const unsigned char *suffix)
{
    const unsigned char *sr;
    const unsigned char *tls_iv;
    const unsigned char *tls_key;
    const unsigned int tls_keysize;
    cb_stencil_enc_t plaintext;
    PRInt32 rc;
    unsigned char *req_text;
    unsigned long req_textlen;

    curveball_ssl_set_flags(ssl_SEND_FLAG_NO_SPLIT);
    rc = PR_Write(ssl, "G", 1);
    if (rc < 0) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr,
		"error: cb_stencil_send_enc PR_Write error %d: %s\n",
		err, PR_ErrorToName(err));
	return -1;
    }

    /* We can't fetch the IV until *after* the PR_Write of
     * the "G" is finished.
     */
    sr = curveball_ssl_get_sr(NULL);
    tls_key = curveball_aes_get_key(&tls_keysize);
    tls_iv = curveball_aes_get_iv();

    if (0) { /* DIAGNOSTIC */
	unsigned int j;

	printf("cb_stencil_send: sr\n");
	for (j = 0; j < 32; j++) {
	    printf("%.2x", sr[j]);
	}
	printf("\n");
	fflush(stdout);
    }

    if (0) { /* DIAGNOSTIC */
	printf("computing stencil\n"); fflush(stdout);
    }

    rc = cb_stencil_aes_create_plaintext(sr, &plaintext,
	    (unsigned char *) "ET /",
	    tls_key, tls_keysize, tls_iv, enc_key, enc_keysize);

    if (rc != 0) {
	fprintf(stderr, "ERROR: cb_stencil_send_enc failed\n");
	return rc;
    }

    if (suffix == NULL) {
	req_textlen = sizeof(plaintext);
	req_text = &plaintext;
    }
    else {
	req_textlen = sizeof(plaintext) + strlen(suffix);
	req_text = malloc(req_textlen + 1);
	if (req_text == NULL) {
	    fprintf(stderr, "error: cb_stencil_send malloc failed\n");
	    return -1;
	}
	memcpy(req_text, &plaintext, sizeof(plaintext));
	memcpy(req_text + sizeof(plaintext), suffix, strlen(suffix));
	req_text[req_textlen] = '\0';
	/* printf("SUFFIX = [%s]\n", suffix); */
	/* printf("PLAINTEXT = [%s]\n", req_text); */
    }

    curveball_ssl_set_flags(ssl_SEND_FLAG_NO_SPLIT);
    rc = PR_Write(ssl, req_text, req_textlen);

    if (req_text != &plaintext) {
	free(req_text);
    }

    if (rc < 0) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr,
		"error: cb_stencil_send_enc PR_Write error %d: %s\n",
		err, PR_ErrorToName(err));
	return -1;
    }

    return 0;
}

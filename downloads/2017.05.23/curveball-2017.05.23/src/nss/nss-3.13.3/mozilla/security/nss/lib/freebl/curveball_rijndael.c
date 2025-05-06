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

#include "curveball_rijndael.h"

#include "rijndael.h"

/*
 * The AES CBC context used for encryption by the current Curveball connection,
 * if any.
 *
 * NOTE: we only track the AES state for the encryption side of one PRFileDesc
 * right now.
 */

static struct AESContextStr *CURVEBALL_AES_ENC_CONTEXT = NULL;

/*
 * The ENC_KEY is the unexpanded AES key used for encryption by the current
 * Curveball connection, if any.  May be filled with junk until initialized.
 *
 * The ENC_KEYSIZE is the length of the key (16 or 32, for different SSL
 * modes).
 */

static unsigned char *CURVEBALL_AES_ENC_KEY = NULL;
static unsigned int CURVEBALL_AES_ENC_KEYSIZE = 0;

/*
 * Note the reference to the AES CBC context used for encryption, so we can
 * peek into it later and extract the IV when necessary.
 *
 * This function may be called many times, but it only records the FIRST
 * value it is called with.
 */
int
curveball_aes_set_context(AESContext *enc)
{
    static int set = 0;

    if (!set) {
	set = 1;
	CURVEBALL_AES_ENC_CONTEXT = (struct AESContextStr *) enc;
    }

    return 0;
}

/*
 * Note the key used by the AES CBC context used for encryption, so we can
 * peek at it later.
 *
 * This function may be called many times, but it only records the FIRST
 * value it is called with.
 */
int
curveball_aes_set_key(const unsigned char *key, unsigned int keysize)
{
    static int set = 0;

    if (!set) {
	set = 1;

	if (keysize > 0) {
	    CURVEBALL_AES_ENC_KEY = malloc(keysize);
	    /* TODO: we should really check that malloc succeeded */

	    memmove(CURVEBALL_AES_ENC_KEY, key, keysize);
	    CURVEBALL_AES_ENC_KEYSIZE = keysize;
	}
    }

    return 0;
}

/*
 * Return a reference to the current IV used by the AES CBC context.
 *
 * This must be treated as read-only, because it's a reference to the real IV.
 *
 * Returns NULL if there is no IV, or the context hasn't been set.
 */
const unsigned char *
curveball_aes_get_iv(void)
{

    if (CURVEBALL_AES_ENC_CONTEXT == NULL) {
	return NULL;
    }
    else {
	if (0) {
	    unsigned int j;

	    printf("got a real IV ");
	    for (j = 0; j < 16; j++) {
		printf("%.2x", CURVEBALL_AES_ENC_CONTEXT->iv[j]);
	    }
	    printf("\n");
	}
	return CURVEBALL_AES_ENC_CONTEXT->iv;
    }
}

/*
 * Return a reference to the current (unexpanded) key used by the AES CBC
 * context, and set the value at the keysize reference to the keysize used.
 * (if the keysize reference is NULL, then don't set it)
 *
 * This must be treated as read-only, because it's a reference to the real IV.
 *
 * Returns NULL (and sets the keysize to zero) if the context hasn't been
 * set (even though this doesn't depend on the context, because it's useless
 * without one).
 */

const unsigned char *
curveball_aes_get_key(unsigned int *keysize)
{

    if (CURVEBALL_AES_ENC_KEY == NULL) {
	if (keysize != NULL) {
	    *keysize = 0;
	}
	return NULL;
    }
    else {
	if (keysize != NULL) {
	    *keysize = CURVEBALL_AES_ENC_KEYSIZE;
	}
	return CURVEBALL_AES_ENC_KEY;
    }
}

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

#include <string.h>
#include <stdio.h>

#include "prerror.h"
#include "prinit.h"
#include "nss.h"
#include "pk11pub.h"
#include "pk11func.h"
#include "secmodi.h"

#include "cb_stencil.h"

static int
test_plaintext_direct(void)
{
    unsigned char iv_buf[16];
    const unsigned char *tls_key = "abcdabcdabcdabcd";
    const unsigned char *enc_key = "1234123412341234";

    cb_stencil_data_t res;
    cb_stencil_enc_t plaintext;

    memset(&res, 0, sizeof(res));

    cb_stencil_aes_create_plaintext(&res, &plaintext,
	    (unsigned char *) "GET /",
	    tls_key, strlen(tls_key), iv_buf,
	    enc_key, strlen(enc_key));

    return 0;
}


int main(int argc, char **argv)
{
    cb_stencil_spec_t *spec = cb_stencil_spec_default(NULL);
    cb_stencil_enc_t *mask = cb_stencil_mask(spec);
    cb_stencil_enc_t data;
    cb_stencil_data_t res;
    unsigned int i;

    PR_Init(0, 0, 0);

    if (NSS_NoDB_Init(".") != SECSuccess) {
	printf("FAILED NSS_NoDB_INIT()\n");
    }

#ifdef NOPE

    for (i = 0; i < STENCIL_MASK_NBYTES; i++) {
	printf("%.2x", mask->bytes[i]);
    }
    printf("\n");

    for (i = 0; i < STENCIL_NBITS; i++) {
	spec->values[i] = 1;
    }

    for (i = 0; i < STENCIL_MASK_NBYTES; i++) {
	data.bytes[i] = 0xff;
    }

    if (cb_stencil_check(&data, spec)) {
	printf("match\n");
    }
    else {
	printf("no match\n");
    }

    for (i = 0; i < STENCIL_NBITS; i++) {
	spec->values[i] = 0;
    }

    for (i = 0; i < STENCIL_MASK_NBYTES; i++) {
	data.bytes[i] = 0xf0;
    }

    if (cb_stencil_check(&data, spec)) {
	printf("match\n");
    }
    else {
	printf("no match\n");
    }

    for (i = 0; i < STENCIL_MASK_NBYTES; i++) {
	data.bytes[i] = 0x01;
    }

    cb_stencil_read(spec, &data, &res);
    for (i = 0; i < STENCIL_NBYTES; i++) {
	printf("%.2x", res.bytes[i]);
    }
    printf("\n");

#endif /* NOPE */

    test_plaintext_direct();

    return 0;

}

#ifndef CURVEBALL_KEYDATA
#define CURVEBALL_KEYDATA yes

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

/* length of AES key used to generate sentinels */
#define CB_SENTINEL_KEYLEN		(256)

#define CB_SENTINEL_HMAC_BYTES		(32)
#define CB_SENTINEL_BYTES		(8)
#define CB_FLOW_ID_SALT_BYTES		(2)
#define CB_SENTINEL_FLOWID_BYTES	(6)
#define CB_SENTINEL_LABEL_BYTES		(CB_SENTINEL_HMAC_BYTES - CB_SENTINEL_BYTES)
#define CB_SENTINEL_SIZE		(28)
#define CB_STENCIL_KEY_BYTES		(16)

#define CB_DP_HELLO_SIGNATURE_OFFSET	(32)
#define CB_AES_KEY_BYTES		(32)
#define CB_HMAC_KEY_BYTES		(64)

#define CURVEBALL_ERROR_SIZE		(256)

/* Sentinel generation makes N (<= CB_MAX_SENTINELS_PER_KEY) sentinels
 * per key.  i, such that (0<= i < N) is an input into the
 * sentinel-generation process.  The client needs to choose an i when
 * making its sentinel, so that i must be less than N.
 *
 * Right now N is a parameter input into the sentinel generation process.
 * It's not clear it should be anything other than a constant, since the
 * clients need to know what the value is, too. 
 */
#define CB_MAX_SENTINELS_PER_KEY        (128)


typedef struct cb_thread_dataStr {
    unsigned char aes_session_key_data[CB_AES_KEY_BYTES];
    SECItem aes_session_key;

    unsigned char hmac_session_key_data[CB_HMAC_KEY_BYTES];
    SECItem hmac_session_key;
    
    unsigned char aes_session_iv_data[CB_AES_KEY_BYTES];
    SECItem aes_session_iv;

    unsigned char sent_sentinel[CB_SENTINEL_BYTES];
    unsigned char sent_sentinel_label[CB_SENTINEL_LABEL_BYTES];

    unsigned char flow_id_salt[CB_FLOW_ID_SALT_BYTES];
} cb_thread_data;

PRBool curveball_set_sentinel(unsigned char *);
PRBool curveball_set_sentinel_label(unsigned char *);
PRBool curveball_set_curveball_hello_key(SECItem *);
PRBool curveball_set_curveball_hello_iv(SECItem *);
unsigned char *curveball_read_key_from_file(char *, int);

#endif /* CURVEBALL_KEYDATA */

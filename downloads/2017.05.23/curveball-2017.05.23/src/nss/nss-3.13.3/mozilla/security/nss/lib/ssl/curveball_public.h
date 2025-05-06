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

#ifndef _curveball_public_h
#define _curveball_public_h

#ifndef TRACE
#define TRACE yes
#endif /* TRACE */

#include "ssl.h"
#include "sslimpl.h"
#include "curveball_keydata.h"

void curveball_printable(char *, unsigned char *, int);
void curveball_asciify(const char *, const unsigned char *, const int);

SECKEYPublicKey *curveball_cert(char *, char *);
PRBool curveball_decoy_proxy_in_path(PRFileDesc *);

int curveball_is_enabled(int);
void curveball_enable(int);
void curveball_errmsg__(char *, char *, int);

#ifdef USE_CURVEBALL_CONFIG
SECStatus curveball_config_value_add(char *, char *);
char *curveball_config_value(char *);
int curveball_config_int(char *);
SECStatus curveball_config_file_read(void);
SECStatus curveball_config(void);
#endif /* USE_CURVEBALL_CONFIG */
void curveball_generate_pms_data(sslSocket *ss, unsigned char *random);

int curveball_debug(void);
SECStatus curveball_generate_sentinel_data(int, unsigned char *, int,
	unsigned char *, unsigned char *);

#define curveball_errmsg(msg) curveball_errmsg__(msg, __FILE__, __LINE__)

extern char curveball_error[];

extern SECItem curveball_aes_session_key;
extern SECItem curveball_aes_session_iv;
extern SECItem curveball_hmac_session_key;

extern char cb_debug;

extern int curveball_aes_keylen;

extern int CURVEBALL_TUNNEL_TYPE; /* 0 = Bidirectional, 1 = Unidirectional */
#define CURVEBALL_BIDIRECTIONAL_TUNNEL 0
#define CURVEBALL_UNIDIRECTIONAL_TUNNEL 1

#endif /* _curveball_public_h */


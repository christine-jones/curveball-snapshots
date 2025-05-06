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

#include "curveball_ssl.h"

/*
 * NOTE: we only track the AES state for the encryption side of one PRFileDesc
 * right now.  The ssl parameter to these functions is ignored.
 */

static unsigned char CURVEBALL_SSL_SERVER_RANDOM[32];
static int CURVEBALL_SSL_FLAGS = 0;


/*
 * Note the ServerRandom string used by the TLS handshake, so we can
 * peek at it later.
 */
int
curveball_ssl_set_sr(PRFileDesc *ssl, const unsigned char *sr)
{

    memmove(CURVEBALL_SSL_SERVER_RANDOM, sr,
	    sizeof(CURVEBALL_SSL_SERVER_RANDOM));

    return 0;
}

/*
 * Return a reference to the ServerRandom used by the TLS handshake.
 *
 * This must be treated as read-only, because it is returned by reference.
 */
const unsigned char *
curveball_ssl_get_sr(PRFileDesc *ssl)
{

    return CURVEBALL_SSL_SERVER_RANDOM;
}

/*
 * Set the flags used by ssl_SecureWrite (and return the previous value
 * of flags).
 */
int
curveball_ssl_set_flags(int flags)
{
    int old_flags = curveball_ssl_get_flags();

    CURVEBALL_SSL_FLAGS = flags;

    return old_flags;
}

/*
 * Return the current flags used by ssl_SecureWrite
 */
int
curveball_ssl_get_flags(void)
{
    return CURVEBALL_SSL_FLAGS;
}

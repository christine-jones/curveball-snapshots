#ifndef _curveball_nss_h
#define _curveball_nss_h

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

#include "curveball_public.h"
#include "ssl.h"
#include "sslimpl.h"

SECStatus curveball_generate_sentinel(sslSocket *, unsigned char *, int);
SECStatus curveball_decode(void *, unsigned char *, int *,
	unsigned int, unsigned char *, int);
int curveball_is_dp_hello(sslSocket *, sslBuffer *);
int curveball_is_dp_hello_uni(sslSocket *, sslBuffer *);

#endif /* _curveball_nss_h */

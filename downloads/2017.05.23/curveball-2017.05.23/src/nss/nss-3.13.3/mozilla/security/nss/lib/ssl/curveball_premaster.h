#ifndef _curveball_premaster_h
#define _curveball_premaster_h

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

#include "pkcs11t.h"

/* Must fit in an unsigned byte */
#define CURVEBALL_PMS_FLAG 0x80
#define CURVEBALL_PMS_RANDOM_BYTES 46
#define CURVEBALL_PMS_TOTAL_BYTES 48

int curveball_is_enabled(int);

typedef struct 
{
    CK_VERSION version;
    unsigned char random[CURVEBALL_PMS_RANDOM_BYTES];
} CURVEBALL_PMS_DATA;

/* This lets us grep for "ifdef CURVEBALL" to find where Curveball has
 * affected libraries other than ssl
 */

#define CURVEBALL_IN_OTHER_LIBRARIES yes

#endif /* _curveball_premaster_h */



#ifndef CURVEBALL_RIJNDAEL_H
#define CURVEBALL_RIJNDAEL_H 1

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

#include "blapi.h"

extern int curveball_aes_set_context(AESContext *enc);
extern int curveball_aes_set_key(const unsigned char *key,
	unsigned int keysize);

extern const unsigned char *curveball_aes_get_iv(void);
extern const unsigned char *curveball_aes_get_key(unsigned int *keysize);

#endif /* CURVEBALL_RIJNDAEL_H */

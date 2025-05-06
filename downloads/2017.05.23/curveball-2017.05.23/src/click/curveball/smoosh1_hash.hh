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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef _SMOOSH1_HASHER_H_
#define _SMOOSH1_HASHER_H_

uint32_t smoosh1_hash(const char *key, uint32_t value_len, uint32_t seed);

/*
 * For use with tools like smhash
 */
inline void smoosh1_hash_test(const void *key, int len,
	uint32_t seed, void *out)
{
    *(uint32_t *)out = smoosh1_hash((const char *)key, len, seed);
}

#endif /* _SMOOSH1_HASHER_H_ */


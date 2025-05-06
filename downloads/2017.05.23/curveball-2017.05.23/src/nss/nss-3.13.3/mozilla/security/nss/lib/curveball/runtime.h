#ifndef runtime_h
#define runtime_h yes

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

/* enough bytes to hold a %d-printed representation of 2^64-1: */
#define HOW_MANY_CHARS_TO_REPRESENT_64BIT_NUMBER 21

extern char *cb_msg_1s(char *fmt, char *arg);
extern char *cb_msg_1i(char *fmt, int arg);
extern int cb_call(int failed, char *msg);
extern int cb_nssCall(int failed, char *msg);
extern int cb_eCall(int failed, char *msg);
extern int cb_eNssCall(int failed, char *msg);

#endif /* runtime_h */

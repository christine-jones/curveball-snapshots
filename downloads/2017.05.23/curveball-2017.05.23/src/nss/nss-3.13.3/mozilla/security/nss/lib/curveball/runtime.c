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

/** \file
 Routines for runtime error checking.

 The general idea is that each may-produce-an-error call appears as some
 variation on

  cb_[e]call(error-condition, error-message-to-produce-if-error-condition-true)

 in order to make it easy for all errors to be checked and useful error
 messages produced on errors.

 cb_eCall() means "exit if error-condition true after printing diagnostic"

 cb_call() means make the call and print the diagnostic on error, returns the
        state of the error condition

 To print the error messages, there are a lot of type-specific functions.
 Newer C compilers make it pretty easy to write variable-length argument
 lists, perhaps these functions should be replaced with those.

 There are also NSS versions of the calls (to provide boilerplate to get
 the error condition out of the NSS library).

 Exiting on error may be a bit heavy-handed.  Might want to use
 setjmp/longjmp to simulate exceptions instead (or something like
 https://code.google.com/p/exceptions4c/ ).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "prerror.h"
#include "prprf.h"

#include "runtime.h"

extern char *progname;

/** Format a buffer with a message that contains one string argument
 * \param fmt A printf format with one '%s' in it
 * \param arg A string for the %s in the format
 * \return A static buffer containing the error message for printing
 */
char *cb_msg_1s(char *fmt, char *arg)
{
    static char ebuf[512];

    if (strlen(fmt) + strlen(arg) > sizeof(ebuf)) {
        return "error message too large to report";
    }
    else {
        PR_snprintf(ebuf, sizeof(ebuf), fmt, arg);
    }
    return ebuf;
}

/** format a buffer with a message that contains one integer argument
 * \param fmt A printf format with one '%d' in it
 * \param arg An integer for the %d in the format
 * \return A static buffer containing the error message for printing
 */
char *cb_msg_1i(char *fmt, int arg)
{
    static char ebuf[512];

    if (strlen(fmt) + HOW_MANY_CHARS_TO_REPRESENT_64BIT_NUMBER > sizeof(ebuf)) {
        return "error message too large to report";
    }
    else {
        PR_snprintf(ebuf, sizeof(ebuf), fmt, arg);
    }
    return ebuf;
}

/** wrap error checking and reporting
 * \param failure_condition Something that should be true, otherwise produce
 *      an error
 * \param message A string containing a message that explains what the
 *      failure condition means.
 * \return The value of failure_condition
 */
int cb_call(int failure_condition, char *message)
{

    if (failure_condition) {
        fprintf(stderr, "%s: %s; %s\n",
		progname, message, strerror(errno));
    }
    return failure_condition;
}

/** wrap error checking, reporting, and exit on error
 * \param failure_condition If true, produce an error message
 * \param message A string containing a message that explains what the
 *      failure condition means
 * \return The value of failure_condition, doesn't return on failure
 */
int cb_eCall(int failure_condition, char *message)
{
    if (cb_call(failure_condition, message)) {
        exit(1);
    }
    return failure_condition;
}

/** wrap error checking and reporting, for use with NSS functions
 * \param failure_condition If true, means produce an error message
 * \param message A string containing a message that explains what the
 *      failure condition means
 * \return The value of failure_condition
*/
int cb_nssCall(int failure_condition, char *message)
{

    if (failure_condition) {
        PRErrorCode err;
        err = PR_GetError();
        fprintf(stderr, "%s: %s; %d/%s\n",
		progname, message, err, PR_ErrorToName(err));
    }
    return failure_condition;
}

/** wrap error checking, reporting and exit on error, suitable for use
 * with NSS routines
 * \param failure_condition If true, cproduce an error message
 * \param message A string containing a message that explains what the
 *      failure condition means
 * \return The value of failure_condition, doesn't return on failure
 */
int cb_eNssCall(int failure_condition, char *message)
{

    if (cb_nssCall(failure_condition, message)) {
        exit(1);
    }
    return failure_condition;
}

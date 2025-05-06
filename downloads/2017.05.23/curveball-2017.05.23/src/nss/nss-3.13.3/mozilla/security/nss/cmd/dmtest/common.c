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

#include <prerror.h>
#include <prmem.h>
#include "prprf.h"

#include <string.h>
#include "common.h"
#include "nss.h"

/* A simple error and exit routine*/
int err_exit(string)
char *string;
{
    PR_fprintf(PR_STDERR,"%s\n",string);
    exit(1);
}

void PR_error(char *string)
{
    char tbuf[128];
    char *tptr = &tbuf[0];

    int errlen = PR_GetErrorTextLength();

    if (errlen > sizeof(tbuf)) {
        tptr = PR_Malloc(errlen + 1);
        if (tptr == NULL) {

            PR_snprintf(tbuf, sizeof(tbuf),
		    "%s; Can't malloc %d bytes for NSS error for code %d.",
		    string, errlen + 1, PR_GetError());
            PR_fprintf(PR_STDERR, tbuf);
            return;
        }
    }
    PR_GetErrorText(tptr);
    PR_fprintf(PR_STDERR, "%s: %s", string, tptr);

    /* We don't get here, but if we did, we should free this memory, if
     * need be.
     */
    if (tptr != &tbuf[0]) {
	free(tptr);
    }
}

/* Print SSL errors and exit*/
void berr_exit(char *string)
{
    char tbuf[128];
    char *tptr = &tbuf[0];
    char outbuf[256];

    int errlen = PR_GetErrorTextLength();

    if (errlen > 0) {
        if (errlen > sizeof(tbuf)) {
            tptr = PR_Malloc(errlen + 1);
            if (tptr == NULL) {

                PR_snprintf(tbuf, sizeof(tbuf),
			"%s; Can't malloc %d bytes for NSS error for code %d",
			string, errlen+1, PR_GetError());
                err_exit(tbuf);
            }
        }
        PR_GetErrorText(tptr);
    }
    else {
        *tptr = '\0';
    }

    PR_snprintf(outbuf, sizeof(outbuf), "%s; %s", string, tptr);
    err_exit(outbuf);

    /* We don't get here, but if we did, we should free this memory, if
     * we had to allocate some.
     */
    if (tptr != &tbuf[0]) {
	free(tptr);
    }
}


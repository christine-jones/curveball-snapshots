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

#include <prio.h>
#include <prenv.h>
#include <prprf.h>
#include <prclist.h>
#include <plstr.h>
#include <prmem.h>
#include <sys/types.h>
#include <base.h>
#include <errno.h>
#include <string.h>

#include "curveball_public.h"

nssList *config_data;

#ifdef USE_CURVEBALL_CONFIG
#include <regex.h>
typedef struct
{
    char *label;
    char *value;
} config_item;

static int curveball_configured = 0;

static PRBool
item_has_label(void *a, void *b)
{
    return (PRBool) (strcmp(((config_item *) a)->label, ((char *) b)) == 0);
}

static config_item *
config_item_make(char *label, char *value)
{
    config_item *item = (config_item *) PR_Calloc(1, sizeof(config_item));

    if (item) {
        item->label = PL_strdup(label);
        item->value = PL_strdup(value);
    }
    if (item == NULL || item->label == NULL || item->value == NULL) {
        if (item) {
            if (item->label) PL_strfree(label);
            if (item->value) PL_strfree(value);
            PR_Free(item);
        }
	PR_snprintf(curveball_error, CURVEBALL_ERROR_SIZE,
		"Can't create config_item ; %s", strerror(errno));
        curveball_errmsg(NULL);
        return NULL;
    }
    return item;
}

static void re_error(regex_t *re, int err, char *msg)
{
    char errbuf[256];
    regerror(err, re, errbuf, sizeof(errbuf));
    PR_snprintf(curveball_error, CURVEBALL_ERROR_SIZE,
	    "Can't compile %s; error %d\n", msg, err);
}

SECStatus
curveball_config_value_add(char *label, char *value)
{
    config_item *item = config_item_make(label, value);

    if (item) {
        nssList_Add(config_data, item);
        return SECSuccess;
    }
    return SECFailure;
}

/* Find the value associated with label
 * returns NULL if not found
 */
char *curveball_config_value(char *label)
{
    config_item *item;

    curveball_config();
    item = nssList_Get(config_data, label);
    if (item) {
	return item->value;
    }
    else {
	return NULL;
    }
}

/* returns -1 on error */
int
curveball_config_int(char *label)
{
    char *value = curveball_config_value(label);

    if (value) {
	return(atoi(value));
    }
    else {
	return -1;
    }
}

static char *drop_trailing_whitespace(char *buf)
{
    int lastchar_index = strlen(buf) - 1;

    while (lastchar_index >= 0 && isspace(buf[lastchar_index])) {
        buf[lastchar_index] = '\0';
        lastchar_index--;
    }
    return buf;
}

SECStatus
curveball_config_file_read(void)
{
    char *config_file;
    FILE *config;
    char *fgot;
    char buffer[1024];
    int lineno;
    regex_t re_assignment;
    regex_t re_blank;
    regex_t re_comment;
    regex_t re_section;
    int err;

    /* matches ^<whitespace># ... */
    if ((err = regcomp(&re_comment, "^[ \t]*#", REG_NOSUB)) != 0) {
        re_error(&re_comment, err, "comment regex");
        curveball_errmsg(NULL);
        return SECFailure;
    }
    /* matches a line consisting just of whitespace */
    if ((err = regcomp(&re_blank, "^[ \t]*\n", REG_NOSUB|REG_NEWLINE)) != 0) {
        re_error(&re_blank, err, "blank-line regex");
        curveball_errmsg(NULL);
        return SECFailure;
    }
    /* matches a python config [section] header
     * which we ignore, but which is also viewed as syntactically correct
     */
    if ((err = regcomp(&re_section, "^[ \t]*\\[.*\\]", REG_NOSUB)) != 0) {
        re_error(&re_section, err, "section regex");
        curveball_errmsg(NULL);
        return SECFailure;
    }
    /* vbl = value # even with a comment and whitespace, extracts vbl and
     * value from the string
     */
    if ((err = regcomp(&re_assignment,
                      "^[ \t]*([^ \t=]+)[ ]*=[ ]*([^#]+).*\n",
                      REG_EXTENDED|REG_NEWLINE)) != 0) {
        re_error(&re_assignment, err, "assignment regex");
        curveball_errmsg(NULL);
        return SECFailure;
    }

    if (curveball_configured) return 1;
    curveball_configured = 1;

    if ((config_data = nssList_Create(NULL, PR_TRUE)) == NULL) {
    	PR_snprintf(curveball_error,
                    CURVEBALL_ERROR_SIZE,
                    "Can't create config_data list; %s",
                    strerror(errno));
        curveball_errmsg(NULL);
        return SECFailure;
    }
    nssList_SetCompareFunction(config_data, item_has_label);
    if ((config_file = PR_GetEnv("CURVEBALL_CONFIG")) == NULL) {
        fprintf(stderr, "CURVEBALL_CONFIG environment variable not set\n");
        exit(1);
    }
    if ((config = fopen(config_file, "r")) == NULL) {
    	PR_snprintf(curveball_error,
                    CURVEBALL_ERROR_SIZE,
                    "Can't open '%s' for reading; %s\n",
                    config_file,
                    strerror(errno));
        curveball_errmsg(NULL);
        return SECFailure;
    }

    lineno = 0;
    while ((fgot = fgets(buffer, sizeof(buffer), config)) != NULL) {
        lineno++;

        if (PL_strlen(fgot) > 0 && buffer[PL_strlen(fgot)-1] != '\n') {
            /* buffer too small for line */
            PR_snprintf(curveball_error,
                        CURVEBALL_ERROR_SIZE,
                        "%s(line %d): line too long\n",
                        config_file,
                        lineno,
                        strerror(errno));
            curveball_errmsg(NULL);
        } else {
#define NMATCH 3
            regmatch_t m[NMATCH];

            if (REG_NOMATCH == regexec(&re_comment, fgot, 0, m, 0)
		    && REG_NOMATCH == regexec(&re_blank, fgot, 0, m, 0)
		    && REG_NOMATCH == regexec(&re_section, fgot, 0, m, 0)) {
                if (0 == regexec(&re_assignment, fgot, NMATCH, m, 0)) {
                    if (m[1].rm_so >= 0 && m[2].rm_so >= 0) {
                        char *label = &fgot[m[1].rm_so];
                        char *value = &fgot[m[2].rm_so];

                        fgot[m[1].rm_eo] = '\0';
                        fgot[m[2].rm_eo] = '\0';
                        curveball_config_value_add(label,
				drop_trailing_whitespace(value));
                    } else {
                        PR_snprintf(curveball_error,
                                    CURVEBALL_ERROR_SIZE,
                                    "%s(line %d): assignment match, but re extracted no values",
                                    config_file,
                                    lineno);
                        curveball_errmsg(NULL);
                    }
                } else {
                    PR_snprintf(curveball_error,
                                CURVEBALL_ERROR_SIZE,
                                "%s(line %d): syntax error",
                                config_file,
                                lineno);
                    curveball_errmsg(NULL);
                }
            }
        }
    }
    fclose(config);
    curveball_configured = 1;
    return SECSuccess;
}
#endif /* USE_CURVEBALL_CONFIG */

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

/*
 * Implements a stateful Oracle that determines whether or not a
 * connection to a given IP/port combination should be treated as an
 * ordinary connection or whether it should be probed to see if there is
 * a DR along the path and/or a covert tunnel should be established if
 * there is.
 *
 * The real decisions are made externally (by the trawler, or by the client
 * agent).  This utility consults the results of those decisions.
 */
/*
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <prio.h>
#include <prenv.h>
#include <prmem.h>
#include <prprf.h>
#include <prlock.h>

#include "nspr.h"
#include "cbchooser.h"


static int cbchooser_config(void);
static cbchooser_record_t *parse_record(const char *text);
static int insert_record(cbchooser_record_t *record);
static cbchooser_record_t *lookup_record(cbchooser_record_t *rec);
static int cbchooser_load_records(cbchooser_config_t *conf);

static void sort_records(void);

static cbchooser_config_t Config;
static cbchooser_mode_t Mode = CBCHOOSER_ALWAYS_PROBE;
static cbchooser_status_t Configured = CBCHOOSER_UNCONFIGURED;

static cbchooser_record_t **Records = NULL;

static int _DEBUG_ = 0;

PRLock* cbchooserLock;

#define MAX_CB_ENV_LEN 127
#define MAX_CB_MAX_ENV_LEN 2047

char *
CB_GetEnv(const char *param_name)
{
    static int initialized = 0;
    static int found_params = 0;
    static char buf[MAX_CB_MAX_ENV_LEN + 1];
    static char *pattern =
	    "CURVEBALL_ENABLE=%s\n"
	    "CBCHOOSER_ROOTDIR=%s\n"
	    "CBCHOOSER_MODE=%s\n"
	    "CBCHOOSER_DEBUG=%s\n";
    static char enabled_str[MAX_CB_ENV_LEN + 1];
    static char rootdir_str[MAX_CB_ENV_LEN + 1];
    static char mode_str[MAX_CB_ENV_LEN + 1];
    static char debug_str[MAX_CB_ENV_LEN + 1];
    PRFileDesc *fin;
    char *ptr;

    /*
     * The format of the file must match the pattern precisely.
     */
    if (!initialized) {
	if (fin = PR_Open("/tmp/cbctl", PR_RDONLY, 0660)) {
	    int cnt = PR_Read(fin, buf, MAX_CB_MAX_ENV_LEN);
	    int rc;

	    PR_Close(fin);

	    if (cnt > 0) {
		buf[cnt] = '\0';
		rc = sscanf(buf, pattern,
			enabled_str, rootdir_str, mode_str, debug_str);
		if (rc == 4) {
		    found_params = 1;
		}

		printf("ENABLE:[%s]\n", enabled_str);
		printf("ROOTDIR:[%s]\n", rootdir_str);
		printf("MODE:[%s]\n", mode_str);
		printf("DEBUG:[%s]\n", debug_str);
	    }
	}

	initialized = 1;
    }

    ptr = PR_GetEnv(param_name);
    if (ptr != NULL) {
	return ptr;
    }
    if (!found_params) {
	return NULL;
    }
    else if (!strcmp("CURVEBALL_ENABLE", param_name)) {
	return enabled_str;
    }
    else if (!strcmp("CBCHOOSER_ROOTDIR", param_name)) {
	return rootdir_str;
    }
    else if (!strcmp("CBCHOOSER_MODE", param_name)) {
	return mode_str;
    }
    else if (!strcmp("CBCHOOSER_DEBUG", param_name)) {
	return debug_str;
    }
    else {
	return NULL;
    }
}


/*
 * A way to turn debugging diagnostics on/off from other modules
 *
 * Also, called with -1 argument, just retrieves the current _DEBUG_
 * setting 
 */
int
cbchooser_debug(int debug)
{
    if (debug > 0)
        _DEBUG_ = debug;
    return _DEBUG_;
}

static void cbc_lock_debug(char* op) 
{
    if(_DEBUG_ > 0)
        fprintf(stderr, "Thread(0x%x): %s\n",
                (unsigned int)PR_GetCurrentThread(), op);
}

cbchooser_status_t
cbchooser_status(void)
{

    /*
     * If we're unconfigured, attempt to configure.
     */
    if (Configured == CBCHOOSER_UNCONFIGURED) {
        cbchooserLock = PR_NewLock();
        cbc_lock_debug("create lock");
        if(cbchooserLock == NULL) {
            fprintf(stderr, "Can't create cbchooser lock");
            exit(1);
        }
            
        /* DEBUG fprintf(stderr, "calling CBCHOOSER_CONFIG\n"); */
        
        cbchooser_config();
    }

    return Configured;
}

/*
 * Figure out what to return to the caller, based on the current mode.
 *
 * In all cases (whether or not probing is enabled) we always updated
 * the request table state, and therefore we always need to do the
 * complete test (we can't simply return 0 if the mode is to disable
 * cbchooser, or 1 if we should always probe).
 */
static int
test_with_mode(int result)
{

    switch (Mode) {
    case CBCHOOSER_USE_CRITERIA:
        return result;
    case CBCHOOSER_ALWAYS_PROBE:
        return 1;
    case CBCHOOSER_NEVER_PROBE:
        return 0;
    default:
        /* shouldn't happen, but if it does, don't probe. */
        return 0;
    }
}

/*
 * Test whether a given addr/des_port/proto connection should be probed.
 *
 * See description in cbchooser.h.
 */
int
cbchooser_test(const char* url, PRUint32 addr, PRUint16 des_port, int proto)
{
    cbchooser_record_t template;
    cbchooser_record_t *rec;
    int rc;
    int result;

    /* DEBUG fprintf(stderr, "CBCHOOSER_MODE: %d\n", Mode); */

    /*
     * If the status is not configured, then do not probe.
     *
     * Note that cbchooser_status() will attempt to configure if
     * necessary.
     */
    if (cbchooser_status() != CBCHOOSER_CONFIGURED) {
        return test_with_mode(0);
    }
    switch(Mode) {
    case CBCHOOSER_ALWAYS_PROBE:
        return 1;
    case CBCHOOSER_USE_CRITERIA:
        /* use the critera spelled out in the rest of this routine */
        break;
    case CBCHOOSER_NEVER_PROBE:
        return 0;
    default:
        return 0;
    }

    PR_Lock(cbchooserLock);
    cbc_lock_debug("lock");

    /*
     * Try to load new records.  It's not an error if there aren't any new
     * records, but it's worth noting if the load fails.  We fall back to
     * the default behavior of the load fails, but this is questionable.
     *
     * TODO: review this decision.
     */
    rc = cbchooser_load_records(&Config);
    if (rc != 0) {
        PR_Unlock(cbchooserLock);
        cbc_lock_debug("unlock");
        return test_with_mode(0);
    }

    template.ipv4_addr = addr;
    template.des_port = des_port;
    template.proto = proto;
    template.maskwidth = 32;

    rec = lookup_record(&template);
    if (rec == NULL) {
        /* No record at all?  Don't probe. */
        result = 0;
    }
    else if (rec->delay-- > 0) {
        /* Record exists, but delayed?  Don't probe. */
        result = 0;
    }
    else {
        /* Record exists and delay has expired. Probe! */
        rec->delay = -1;
        printf("yow: %u matched %u/%u\n", addr, rec->ipv4_addr, rec->maskwidth);
        result = 1;
    }

    PR_Unlock(cbchooserLock);
    cbc_lock_debug("unlock");
    return test_with_mode(result);
}

int
cbchooser_result(const char* url, PRUint32 addr, PRUint16 des_port, cbchooser_proto_t proto, int result)
{
    char path[1024]; /* lazy; make this dynamic */
    char tmp_path[1024]; /* lazy; make this dynamic */
    char proto_char = 'x';
    char *result_str = "U";
    int rc;
    PRFileDesc *fout;
    PRUint32 h_addr;

    if(Mode == CBCHOOSER_NEVER_PROBE) return 0;

    /*
     * If the status is not configured, then do not probe.
     *
     * Note that cbchooser_status() will attempt to configure if
     * necessary.
     */
    if (cbchooser_status() != CBCHOOSER_CONFIGURED) {
        return 0;
    }

    switch (proto) {
    case CBCHOOSER_SOCK_STREAM:
        proto_char = 'T';
        break;
    case CBCHOOSER_SOCK_DGRAM:
        proto_char = 'U';
        break;
    default:
        proto_char = 'x';
        break;
    }

    if (result) {
        result_str = "Y";
    }
    else {
        result_str = "N";
    }

    h_addr = PR_ntohl(addr);

    rc = PR_snprintf(tmp_path, sizeof(tmp_path), "%s/%u.%u.%u.%u:%u-%c-x",
                     Config.res_dir,
                     (h_addr >> 24) & 0xff, (h_addr >> 16) & 0xff,
                     (h_addr >> 8) & 0xff, h_addr & 0xff,
		     PR_htons(des_port), proto_char);
    if (rc == (sizeof(path) - 1)) {
        /* if the path appears to be truncated, then we failed. */
        return -1;
    }

    /*
     * tmp_path is always longer than path, so if tmp_path fit then
     * path will also fit.
     */
    rc = PR_snprintf(path, sizeof(path), "%s/%u.%u.%u.%u:%u-%c",
                     Config.res_dir,
                     (h_addr >> 24) & 0xff, (h_addr >> 16) & 0xff,
                     (h_addr >> 8) & 0xff, h_addr & 0xff,
		     PR_htons(des_port), proto_char);

    PR_Lock(cbchooserLock);
    cbc_lock_debug("lock");

    PR_Delete(tmp_path); /* ok if it fails; it might not exist */
    PR_Delete(path); /* ok if it fails; it might not exist */

    /*
     * We can't create and write a file atomically, so we create a temp
     * file, fill it in, and then rename it to the new file.  (rename is
     * atomic)
     */
    fout = PR_Open(tmp_path, PR_TRUNCATE | PR_CREATE_FILE | PR_WRONLY, 0440);
    if (fout == NULL) {
        /* FIXME: log the error */
        fprintf(stderr, "cbchooser Can't open %s for writing\n", tmp_path);
        PR_Unlock(cbchooserLock);
        cbc_lock_debug("unlock");
        return -1;
    }
    rc = PR_Write(fout, result_str, strlen(result_str));
    if (rc != strlen(result_str)) {
        /* FIXME: log the error */
        fprintf(stderr, "cbchooser Can't write to %s\n", tmp_path);
        PR_Close(fout);
        PR_Unlock(cbchooserLock);
        cbc_lock_debug("unlock");
        return -1;
    }

    PR_Close(fout);

    if (PR_SUCCESS != PR_Rename(tmp_path, path)) {
        /* FIXME: log the error */
        fprintf(stderr, "cbchooser Can't rename %s to %s\n", tmp_path, path);
        PR_Unlock(cbchooserLock);
        cbc_lock_debug("unlock");
        return -1;
    }

    PR_Unlock(cbchooserLock);
    cbc_lock_debug("unlock");
    return 0;
}

cbchooser_mode_t
cbchooser_mode(cbchooser_mode_t mode)
{

    cbchooser_mode_t old_mode = Mode;

    /* DEBUG fprintf(stderr, "cbchooser set mode from: %d to %d\n", Mode, mode); */
    
    switch (mode) {
    case CBCHOOSER_NEVER_PROBE:
    case CBCHOOSER_ALWAYS_PROBE:
    case CBCHOOSER_USE_CRITERIA:
        Mode = mode;
        break;
    default:
        /* we got junk */
        break;
    }

    return old_mode;
}

/*
 * Make sure that a directory exists for the given path, creating it if
 * necessary,
 *
 * Originally this test included checking that it's owned by the effective
 * caller and has perms 0700 (or more), but that fell by the wayside with
 * the conversion to NSPR
 *
 * This is a bit special-purpose.
 */

static int
safe_mkdir(const char *path)
{
    unsigned int dir_perms = 0700; /* it's all about me */
    PRFileInfo info;
    int rc;

    PR_MkDir(path, dir_perms);
    rc = PR_GetFileInfo(path, &info);
    if (rc != PR_SUCCESS) {
        return -1;
    }
    else if (info.type != PR_FILE_DIRECTORY) {
        return -1;
    }
    /* else if (statbuf.st_uid != geteuid()) { */
    /*   return -1; */
    /* } */
    else {
        return 0;
    }
}

static int
cbchooser_config(void)
{
    unsigned int i;
    char *root_dir = CB_GetEnv(CBCHOOSER_ROOT_ENV);
    char *mode_str = CB_GetEnv(CBCHOOSER_MODE_ENV);
    char *debug_str = CB_GetEnv(CBCHOOSER_DEBUG_ENV);
    int rc;
    
    unsigned int num_entries;
    cbchooser_mode_t mode = CBCHOOSER_USE_CRITERIA;

    if (root_dir == NULL) {
        Configured = CBCHOOSER_CONF_FAILED;
        return -1;
    }

    if (mode_str != NULL) {
        char *endptr;
        long tmp_mode;

        tmp_mode = strtol(mode_str, &endptr, 0);
        /* if conversion failed, then give up */
        if ((endptr == mode_str) || (*endptr != '\0')) {
            /* we got junk */
            fprintf(stderr, "%s environment variable has bad value: %s\n",
                    CBCHOOSER_MODE_ENV, mode_str);
        }
        else {
            mode = tmp_mode;
        }
        /* DEBUG fprintf(stderr,
		"cbchoser_config: mode_str: '%s'; tmp_mode: %d; mode: %d\n",
                mode_str, tmp_mode, mode); */
        cbchooser_mode(mode);
    }

    /* FIXME - debugging only */
    /* mode = CBCHOOSER_ALWAYS_PROBE; */
    /* cbchooser_mode(mode); */

    if(mode == CBCHOOSER_NEVER_PROBE)
        return -1;

    if(debug_str != NULL){
        _DEBUG_ = atoi(debug_str);
    }
    if(_DEBUG_ > 0) {
        printf("cbchooser_config\n");
    }

    num_entries = 80; /* FIXME should not be hardwired */

    /* TODO: check that num_entries is sensible. */

    /*
     * If we're already configured, scrub the current config and restart
     * from a clean state.
     */

    if (Configured == CBCHOOSER_CONFIGURED) {
        if (Config.req_dir != NULL) {
            free((void *) Config.req_dir);
        }
        if (Config.res_dir != NULL) {
            free((void *) Config.res_dir);
        }
        if (Records != NULL) {
            free(Records);
        }

        Config.num_entries = 0;
        Config.req_dir = NULL;
        Config.res_dir = NULL;
        Records = NULL;
    }

    if (safe_mkdir(root_dir)) {
        /* TODO: fatal error */
        /* FIXME: log */
        Configured = CBCHOOSER_CONF_FAILED;
        if (_DEBUG_) {
            printf("problem with [%s]\n", root_dir);
        }
        return -1;
    }

    Config.num_entries = num_entries;

    Config.req_dir = PR_Malloc(strlen(root_dir)
                               + strlen(CBCHOOSER_REQ_SUBDIR) + 2);
    Config.res_dir = PR_Malloc(strlen(root_dir)
                               + strlen(CBCHOOSER_REQ_SUBDIR) + 2);

    if ((Config.req_dir == NULL) || (Config.res_dir == NULL)) {
        /* TODO: fatal error */
        /* clean up */
        Configured = CBCHOOSER_CONF_FAILED;
        return -1;
    }

    sprintf((char *) Config.req_dir, "%s/%s", root_dir, CBCHOOSER_REQ_SUBDIR);
    sprintf((char *) Config.res_dir, "%s/%s", root_dir, CBCHOOSER_RES_SUBDIR);

    if (safe_mkdir(Config.req_dir)) {
        /* TODO: fatal error */
        /* FIXME: log */
        Configured = CBCHOOSER_CONF_FAILED;
        if (_DEBUG_) {
            printf("problem with [%s]\n", Config.req_dir);
        }
        return -1;
    }

    if (safe_mkdir(Config.res_dir)) {
        /* TODO: fatal error */
        /* FIXME: log */
        Configured = CBCHOOSER_CONF_FAILED;
        if (_DEBUG_) {
            printf("problem with [%s]\n", Config.res_dir);
        }
        return -1;
    }

    Records = PR_Malloc(num_entries * sizeof(cbchooser_record_t *));
    for (i = 0; i < Config.num_entries; i++) {
        Records[i] = (cbchooser_record_t *) NULL;
    }

    Configured = CBCHOOSER_CONFIGURED;

    return 0;
}

#define MAX_SEQNO ((PRUint64) 0xffffffffffffffffL)
static PRUint64 CurrentSeqNo = 1;

static int
cbchooser_load_records(cbchooser_config_t *conf)
{
    PRDir *dir;
    PRDirEntry *ent_p;
    int rc;
    char path[1024]; /* lazy; make this dynamic */
    cbchooser_record_t *rec;
    unsigned int insert_count = 0;

    dir = PR_OpenDir((const char *) conf->req_dir);
    if (dir == NULL) {
        /* TODO log the error */
        return -1;
    }

    for (;;) {
        ent_p = PR_ReadDir(dir, PR_SKIP_BOTH);
        if (ent_p == NULL) {
            break;
        }

        rec = parse_record(ent_p->name);
        if (rec) {
            if (!insert_record(rec)) {
                insert_count++;
            }
        }

        PR_snprintf(path, sizeof(path), "%s/%s", conf->req_dir, ent_p->name);
        rc = PR_Delete(path);
        if (rc != PR_SUCCESS) {
            /* TODO log the error */
        }
    }

    if (insert_count > 0) {
        sort_records();
    }

    PR_CloseDir(dir);
    return 0;
}

static int
addr_within_net(PRUint32 ipv4addr, PRUint32 netaddr, PRUint32 maskwidth)
{
    PRUint32 netmask;

    /*
     * I don't know whether this is a bug in our compiler, or a new part
     * of the C spec, but shifting a 32-bit word by 32 does NOT give zero;
     * it has no effect at all.  Therefore we need to handle a full 32-bit
     * maskwidth as a special case.
     */
    if (maskwidth == 32) {
        netmask = 0xffffffff;
    }
    else {
        netmask = ~(0xffffffff >> maskwidth);
    }

    /*
     * if everything is in canonical format, then we shouldn't
     * need to mask out the netaddr, but better safe than sorry.
     */

    if (_DEBUG_) {
        printf("addr %x network %x subnet %x maskwidth %d\n",
               ipv4addr, netaddr, netmask, maskwidth);
    }

    return (ipv4addr & netmask) == (netaddr & netmask);
}

static cbchooser_record_t *
lookup_record(cbchooser_record_t *rec)
{
    unsigned int i;
    cbchooser_record_t *oldrec;

    if (Configured != CBCHOOSER_CONFIGURED) {
        fprintf(stderr, "cbchooser lookup_record called when not configured (%d)\n",
                Configured);
        return NULL; /* TODO: log the error */
    }

    for (i = 0; i < Config.num_entries; i++) {
        if (Records[i] == NULL) {
            continue;
        }
        else if (Records[i]->delay < 0) {
            /* Clean up expired records as we find them */
            printf("cleaning up %.2u %.8x/%u\n",
                   i, Records[i]->ipv4_addr, Records[i]->maskwidth);
            Records[i] = NULL;
            continue;
        }
        else {
            oldrec = Records[i];

#ifdef DEBUG
	    /* DEBUGGING */
            if (!addr_within_net(rec->ipv4_addr,
                                 oldrec->ipv4_addr, oldrec->maskwidth)) {
		fprintf(stderr, "DEBUG: failed addr in net");
	    }
	    if (oldrec->des_port != rec->des_port) {
		fprintf(stderr, "DEBUG: failed port check %d %d",
			oldrec->des_port, rec->des_port);
	    }
	    if (oldrec->proto != rec->proto) {
		fprintf(stderr, "DEBUG: failed proto check %d %d",
			oldrec->proto, rec->proto);
	    }
	    /* end DEBUGGING */
#endif /* DEBUG */

            /* if we find an old record for this address, return it */
            if ((addr_within_net(rec->ipv4_addr,
                                 oldrec->ipv4_addr, oldrec->maskwidth)) &&
                (oldrec->des_port == rec->des_port) &&
                (oldrec->proto == rec->proto)) {
                return oldrec;
            }
        }
    }

    return NULL;
}

static void
print_records(void)
{
    unsigned int i;

    for (i = 0; i < Config.num_entries; i++) {
        cbchooser_record_t *rec = Records[i];

        if (rec != NULL) {
            printf("%.2u %.8x/%u\n", i, rec->ipv4_addr, rec->maskwidth);
        }
    }
}

static int
compare_records(const void *_a, const void *_b)
{
    cbchooser_record_t *a = *(cbchooser_record_t **) _a;
    cbchooser_record_t *b = *(cbchooser_record_t **) _b;

    if ((a == NULL) || (b == NULL)) {
        if (a == b) {
            return 0;
        }
        else {
            return (a == NULL) ? 1 : -1;
        }
    }
    else {
        if (a->maskwidth == b->maskwidth) {
            /*
             * we could sort more deeply based on operator and ipaddr, but
             * right now we only compare maskwidths.
             */
            return 0;
        }
        else {
            return (a->maskwidth < b->maskwidth) ? 1 : -1;
        }
    }
}

static void
sort_records(void)
{

    if (_DEBUG_) {
        printf("pre-sort:\n");
        print_records();
    }

    qsort(Records, Config.num_entries, sizeof(cbchooser_record_t *),
          compare_records);

    if (_DEBUG_) {
        printf("post-sort:\n");
        print_records();
    }

}

static int
insert_record(cbchooser_record_t *rec)
{
    unsigned int i;
    int open_index = -1;
    PRUint64 oldest_seqno = MAX_SEQNO;
    unsigned int oldest_seqno_index = 0;
    cbchooser_record_t *oldrec;

    if (Configured != CBCHOOSER_CONFIGURED) {
        fprintf(stderr, "cbchooser insert_record called when not configured: %d\n",
                Configured);
        return -1; /* TODO: log the problem */
    }

    /*
     * Assign the sequence number for this record.  This depends on when
     * the record is inserted, not when it is created (for example, if a
     * record is re-inserted, then it gets an updated seqno) so we ignore
     * whatever is currently in the field.
     */
    rec->seqno = CurrentSeqNo++;

    /* TODO: do something graceful when CurrentSeqNo wraps.  Renormalize,
     * or just start over.
     */

    for (i = 0; i < Config.num_entries; i++) {
        if (Records[i] == NULL) {
            if (open_index < 0) {
                open_index = i;
            }
        }
        else {
            oldrec = Records[i];

            if (oldest_seqno > oldrec->seqno) {
                oldest_seqno = oldrec->seqno;
                oldest_seqno_index = i;
            }

            /* if we find an old record for this address, replace it */
            if ((oldrec->ipv4_addr == rec->ipv4_addr) &&
                (oldrec->des_port == rec->des_port) &&
                (oldrec->proto == rec->proto)) {
                if (oldrec != rec) {
                    free(oldrec);
                    Records[i] = rec;
                }
                return 0;
            }
        }
    }

    /*
     * If we didn't find a match for the address, then we'll fall out of
     * the previous loop.  If we found any open slots, then shove the record
     * into the first open slot we found.
     *
     * If we didn't find a match for the address, and all of the slots are
     * filled, then kick out the record with the oldest seqno and insert
     * the new record in its slot.
     */
    if (open_index >= 0) {
        Records[open_index] = rec;
        return 0;
    }
    else {
        oldrec = Records[oldest_seqno_index];

        if (_DEBUG_) {
            printf("kicking out record with seqno %lld\n", oldrec->seqno);
        }

        if (oldrec != rec) {
            free(oldrec);
        }
        Records[oldest_seqno_index] = rec;
        return 0;
    }
}

static cbchooser_record_t *
make_record(PRUint32 addr, PRUint32 maskwidth,
            PRUint16 port, cbchooser_proto_t proto, char op, int delay)
{
    cbchooser_record_t *rec = PR_Malloc(sizeof(cbchooser_record_t));

    if (rec == NULL) {
        return NULL;
    }

    rec->ipv4_addr = addr;
    rec->maskwidth = maskwidth;
    rec->des_port = port;
    rec->proto = proto;
    rec->op = op;
    rec->delay = delay;
    rec->seqno = 0; /* assigned later */

    return rec;
}

static cbchooser_record_t *
parse_record(const char *text)
{
    unsigned int addr[4];
    unsigned int port;
    char op;
    unsigned int delay;
    int rc;
    cbchooser_record_t *rec;
    PRUint32 ipv4_addr;
    PRUint32 maskwidth;
    char proto_char;
    cbchooser_proto_t proto;

    rc = sscanf(text, "%u.%u.%u.%u@%u:%u:%c-%c%u",
                &addr[0], &addr[1], &addr[2], &addr[3],
                &maskwidth, &port, &proto_char, &op, &delay);

    if (rc != 9) {
        if (_DEBUG_) {
            printf("broken [%s]\n", text);
        }
        return NULL;
    }

    /* there are other nonsensical values, but we trust the caller */
    if (maskwidth > 32) {
        maskwidth = 32;
    }

    switch (proto_char) {
    case 'T' :
        proto = CBCHOOSER_SOCK_STREAM;
        break;
    case 'U' :
        proto = CBCHOOSER_SOCK_DGRAM;
        break;
    default :
        proto = CBCHOOSER_SOCK_STREAM; /* punt on everything else */
        break;
    }

    if (_DEBUG_) {
        int proto_char;

        if (proto == CBCHOOSER_SOCK_STREAM) {
            proto_char = 'T';
        }
        else if (proto == CBCHOOSER_SOCK_DGRAM) {
            proto_char = 'U';
        }
        else {
            proto_char = '?';
        }

        printf("addr %u.%u.%u.%u/%u port %u proto %c op %c delay %u\n",
               addr[0], addr[1], addr[2], addr[3],
               maskwidth, port, proto_char, op, delay);
    }

    ipv4_addr = (addr[0] << 24) |  (addr[1] << 16) | (addr[2] << 8) | addr[3];
    ipv4_addr = PR_ntohl(ipv4_addr);
    rec = make_record(ipv4_addr, maskwidth, port, proto, op, delay);

    return rec;
}

cbchooser_config_t*
cbchooser_config_get() 
{
    return &Config;
}


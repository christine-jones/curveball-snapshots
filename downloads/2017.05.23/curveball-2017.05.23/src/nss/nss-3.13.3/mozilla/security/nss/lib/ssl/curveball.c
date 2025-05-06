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

#include <sys/types.h>
#include <sys/stat.h>
/*#include <sys/time.h>*/
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "nspr.h"
#include "prio.h"
#include "prprf.h"
#include "plstr.h"
#include "pkcs11.h"
#include "ssl.h"
#include "nss.h"
#include "pk11pub.h"
#include "pk11func.h"
#include "keyhi.h"
#include "sechash.h"
#include "blapi.h"
#include "curveball_nss.h"
#include "curveball_premaster.h"
#include "curveball_public.h"
#include "cbchooser.h"
#include "cryptohi.h"
#include "secerr.h"
#include "cert.h"

int CURVEBALL_TUNNEL_TYPE = CURVEBALL_BIDIRECTIONAL_TUNNEL;

#define DEBUGPR(a, b)  if (curveball_debug() >= a) fprintf b

#define CB_MIN(x, y) (((x) < (y)) ? (x) : (y))

int CB_PER_DAY_SENTINELS = 0;

/* FIXME --- should be thread-specific */
static unsigned char sentinel[] = { '\xDE', '\xAD', '\xBE', '\xEF',
                                    '\0',   '\0',   '\0',   '\0',
                                    '\0',   '\0',   '\0',   '\0',
                                    '\0',   '\0',   '\0',   '\0',

                                    '\0',   '\0',   '\0',   '\0',
                                    '\0',   '\0',   '\0',   '\0',
                                    '\0',   '\0',   '\0',   '\0',
                                    '\0',   '\0',   '\0',   '\0' };

/* FIXME --- should be thread-specific */
static unsigned char sentinel_label[CB_SENTINEL_LABEL_BYTES];

/* written only once */
static int enable_curveball = -1;

/* There's only one of these per program.
 */
static SECKEYPublicKey *curveball_public_key;

/* this can be written by multiple threads.  We'll just have to live with
 * the results.
 */
char curveball_error[CURVEBALL_ERROR_SIZE];

/* This value was once-upon-a-time generated through magic inside the
 * OpenSSL code.  Now it's a constant extracted from the workings of
 * CT_DP.py with the help of the following bit of python:
 *
 #!/usr/bin/env python

 import binascii

 sentinel_key_hex =                                                     \
 '05f4ca326014f56664c5044bcf35f932b404578034728de4c80435f7bd777f81'
 _sentinel_key = binascii.unhexlify(sentinel_key_hex)

 print _sentinel_key

 * However, it doesn't have to be this way.  This is used only to build
 * the session key, which is then transmitted to the DP encrypted with the
 * Curveball public key (FIXME: is it a problem for the DP to know the
 * curveball private key to do the decryption?).  These bytes could be
 * generated using a random number generator.
 *
 * See
 * http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn5.html#Generate_a_Symmetric_Key
 *
 * See also curveball_generate_aes_session_key
 */

static unsigned char session_key_template[CB_AES_KEY_BYTES] = {
    '\x05', '\xf4', '\xca', '2',
    '`',    '\x14', '\xf5', 'f',
    'd',    '\xc5', '\x04', 'K',
    '\xcf', '5',    '\xf9', '2',

    '\xb4', '\x04', 'W',    '\x80',
    '4',    'r',    '\x8d', '\xe4',
    '\xc8', '\x04', '5',    '\xf7',
    '\xbd', 'w',    '\x7f', '\x81'
};

/* This needs to be a global because it is initialized by user-programs
 * before there are sockets to associate the state with.  This is okay ---
 * it gets initialized once (probably before there are any threads to
 * worry about), and is only read thereafter.
 */
/* FIXME: shouldn't this be thread-specific? */
unsigned char curveball_aes_curveball_hello_key_data[CB_AES_KEY_BYTES];
SECItem curveball_aes_curveball_hello_key = {
    0,
    curveball_aes_curveball_hello_key_data,
    sizeof(curveball_aes_curveball_hello_key_data)
};

/* FIXME: shouldn't this be thread-specific? */
unsigned char curveball_aes_curveball_hello_iv_data[CB_AES_KEY_BYTES];
SECItem curveball_aes_curveball_hello_iv = {
    0,
    curveball_aes_curveball_hello_iv_data,
    sizeof(curveball_aes_curveball_hello_iv_data)
};

/* Control curveball debug verbosity using environment variables.
 * Returns integer debug level, so we can tune verbosity.
 */
int curveball_debug(void)
{
    static int curveball_debug_initialized = 0;
    static int CB_DEBUG = 0;

    char *dbgenv = PR_GetEnv("DEBUG_CURVEBALL");
    if (dbgenv) {
        CB_DEBUG = atoi(dbgenv);
    }
    curveball_debug_initialized = 1;
    return CB_DEBUG;
}

/* Initialize socket-specific data,
 */
void curveball_thread_init(sslSocket *ss)
{
    cb_thread_data *cbt = &ss->cbt;

    if (curveball_is_enabled(2)) {
        DEBUGPR(1, (stderr, "curveball_thread_init(socket %x) thread %x\n",
                    (unsigned int) ss, (unsigned int)PR_GetCurrentThread()));

        /* keys are generated by curveball_send_session_key */
        memset(cbt->aes_session_key_data, 0, CB_AES_KEY_BYTES);
        memcpy(cbt->aes_session_key_data, session_key_template, CB_AES_KEY_BYTES);
        cbt->aes_session_key.type = 0;
        cbt->aes_session_key.data = cbt->aes_session_key_data;
        cbt->aes_session_key.len = CB_AES_KEY_BYTES;

        memset(cbt->aes_session_iv_data, 0, CB_AES_KEY_BYTES);
        cbt->aes_session_iv.type = 0;
        cbt->aes_session_iv.data = cbt->aes_session_iv_data;
        cbt->aes_session_iv.len = CB_AES_KEY_BYTES;

        memset(cbt->hmac_session_key_data, 0, CB_HMAC_KEY_BYTES);
        cbt->hmac_session_key.type = 0;
        cbt->hmac_session_key.data = cbt->hmac_session_key_data;
        cbt->hmac_session_key.len = CB_HMAC_KEY_BYTES;
    }
}

static PRBool
curveball_set_aes(SECItem *dest, SECItem *src)
{
    DEBUGPR(1, (stderr, "curveball_set_aes thread %x\n",
                (unsigned int)PR_GetCurrentThread()));

    if (src->len > dest->len) {
    	PR_snprintf(curveball_error,
                    sizeof(curveball_error),
                    "src key len (%d) larger than dest storage space (%d)",
                    src->len,
                    dest->len);
        PORT_SetError(SEC_CURVEBALL_ERROR);
        return PR_FALSE;
    }

    memcpy(dest->data, src->data, dest->len < src->len? dest->len: src->len);
    if (src->len < dest->len) {
        memset(&dest->data[src->len], 0, (dest->len - src->len));
        dest->len = src->len;
    }

    return PR_TRUE;
}

static void
pp_key(SECKEYPublicKey *key)
{

    fprintf(stderr, "KEY type %d\n", key->keyType);
    switch (key->keyType) {
	case rsaKey:
	    fprintf(stderr, "  pubExp len %d type %d\n",
		    key->u.rsa.publicExponent.len,
		    key->u.rsa.publicExponent.type);
	    fprintf(stderr, "  pubMod len %d type %d\n",
		    key->u.rsa.modulus.len, key->u.rsa.modulus.type);
	    break;
	default:
	    fprintf(stderr, "    UNKNOWN TYPE\n");
    }
}

SECKEYPublicKey *
curveball_cert(char *certfile, char *password)
{
    SECKEYPublicKey *pubkey;
    CERTCertificate *cert;

    cert = PK11_FindCertFromNickname(certfile, password);
    if (cert == NULL) {
    	PR_snprintf(curveball_error,
                    sizeof(curveball_error),
                    "Can't find certificate %s",
                    certfile);
        PORT_SetError(SEC_CURVEBALL_ERROR);
        return NULL;
    }
    pubkey = CERT_ExtractPublicKey(cert);

    if (pubkey == NULL) {
    	PR_snprintf(curveball_error,
                    sizeof(curveball_error),
                    "Can't find public key for cert %s",
                    certfile);

        PORT_SetError(SEC_CURVEBALL_ERROR);
        return NULL;
    }
    return (curveball_public_key = pubkey);
}

/*
 * Called by a user program to initialize the sentinel.  Sentinel should
 * have been produced from curveball_generate_sentinel_data or obtained
 * from the sentinel manager (or, with the cooperation of the DR and the
 * DP, the sentinel may be a fixed field like "deadbeef" for debugging).
 */
PRBool
curveball_set_sentinel(unsigned char *sentinel_in)
{
    /* FIXME: should be thread specific */
    memcpy(sentinel, sentinel_in, CB_SENTINEL_BYTES);
    return PR_TRUE;
}

/* Called by a user program to initialize the sentinel label.  See comment
 * before curveball_set_sentinel
 */
PRBool
curveball_set_sentinel_label(unsigned char *sentinel_label_in)
{
	/* FIXME: should be thread specific */
    memcpy(sentinel_label, sentinel_label_in, CB_SENTINEL_LABEL_BYTES);
    return PR_TRUE;
}

/*
 * Called by a user program to set the "hello key"
 */
PRBool
curveball_set_curveball_hello_key(SECItem *newkey)
{
    /* FIXME: shouldn't this be thread-specific? */
    curveball_asciify("Setting new aes key: ", newkey->data, 32);

    if (curveball_set_aes(&curveball_aes_curveball_hello_key, newkey)) {
        return PR_TRUE;
    }
    return PR_FALSE;
}

PRBool
curveball_set_curveball_hello_iv(SECItem *newkey)
{
    /* FIXME: shouldn't this be thread-specific? */
    if (curveball_set_aes(&curveball_aes_curveball_hello_iv, newkey)) {
        return PR_TRUE;
    }
    return PR_FALSE;
}

PRBool
curveball_decoy_proxy_in_path(PRFileDesc *sslf)
{
    sslSocket *ss = ssl_FindSocket(sslf);
    return ss->ssl3.curveball_got_dp_hello;
}

/* having a level lets us turn on one bit of curveball at a time, when
 * testing or looking for an explanation of why things are hanging
 */
int
curveball_is_enabled(int level)
{
    char *envar;

    if (enable_curveball == -1) {
        if (!curveball_cert("curveball", "curveball")) {
            fprintf(stderr, "Can't get curveball cert info: %s\n",
                    curveball_error);
            enable_curveball = 0;
            return 0;
        }

        if ((envar = CB_GetEnv("CURVEBALL_ENABLE"))) {
            enable_curveball = atoi(envar);
        }
        else {
            enable_curveball = 0;
        }

        (void) curveball_debug();

        /* if (enable_curveball) */
        /*     curveball_config(); */
        DEBUGPR(1, (stderr, "curveball_is_enabled: %d; thread %x\n",
                    enable_curveball, (unsigned int)PR_GetCurrentThread()));
    }
    return enable_curveball > level;
}

/* Sets enable_curveball to value.
 * returns old value of enable_curveball
 */
void
curveball_enable(int value)
{
    enable_curveball = value;
}

SECStatus
curveball_getpeer(sslSocket *ss)
{
    if (! ss->peername_valid) {
        if (ss->ops->getpeername(ss, &ss->peername) != PR_SUCCESS) {
            /* can't tell if we should probe, so don't probe */
            return SECFailure;
        }
	else {
            ss->peername_valid = PR_TRUE;
        }
    }
    return SECSuccess;
}
#define CB_BITS_PER_BYTE 8 /* TODO -- should come from bits.h */

SECStatus
curveball_generate_sentinel(sslSocket *ss, unsigned char *data, int len) {

    unsigned int byte_offset = len - 1;
    unsigned char xor_byte = sentinel_label[CB_SENTINEL_LABEL_BYTES - 1];
    int i = 0;

    if (curveball_getpeer(ss) != SECSuccess) {
        fprintf(stderr, "GETPEER FAILED\n");
        return SECFailure;
    }
    else {
        if (! cbchooser_test(ss->url, ss->peername.inet.ip,
		    PR_ntohs(ss->peername.inet.port),
		    CBCHOOSER_SOCK_STREAM)) {
            fprintf(stderr, "CBCHOOSER SAID NO\n");
            return SECFailure;
        }
    }

    /* begin by populating the sentinel with random bits */
    PK11_GenerateRandom(data, len);

    /* Now overwrite with the curveball-generated sentinel bits */
    memcpy(data, sentinel, CB_SENTINEL_BYTES < len ? CB_SENTINEL_BYTES : len);

    /* For tls-unidirectional, we set bit 0 in the last byte of
     * the data to 0
     * For tls-bidirectional, we set bit 0 in the last byte of
     * the data to 1
     *
     * We then xor the last byte of the data with the last byte of the
     * sentinel label, to encrypt the indicator bit.
     */
    if (CURVEBALL_TUNNEL_TYPE == CURVEBALL_UNIDIRECTIONAL_TUNNEL) {
	data[byte_offset] |= 1;
    }
    else {
	data[byte_offset] &= ~1;
    }
    data[byte_offset] ^= xor_byte;

    /*
    for (i = 0; i < 24; i++) {
	printf("%.2x", sentinel_label[i]);
    }
    printf("\n");
    */

    memset(ss->cbt.sent_sentinel, '\0', CB_SENTINEL_BYTES);
    memcpy(ss->cbt.sent_sentinel, sentinel,
           CB_SENTINEL_BYTES < len? CB_SENTINEL_BYTES: 0);

    curveball_asciify("SENTINEL ", data, len);

    return SECSuccess;
}

void
curveball_printable(char *prefix, unsigned char *buf, int len)
{
    if (prefix != NULL) {
        printf("\n%s: (len %d)", prefix, len);
    }

    if (buf == NULL) {
	printf("NULL buf ptr");
    }
    else {
        int i;

        for (i = 0; i < len && i < 80; i++) {
            if (isspace(buf[i])) {
		printf(" ");
	    }
            else if (isprint(buf[i])) {
		printf("%c", buf[i]);
	    }
            else {
		printf(".");
	    }
        }
        if (i >= 80) {
	    printf(". . . .");
	}
    }
    if (prefix) {
	printf("\n");
    }
}

void
curveball_asciify(const char *prefix, const unsigned char *buf, const int len)
{
    int i;

    if (curveball_debug() == 0) {
	return;
    }

    /* Use this when you have to reproduce this routine in other libraries */
    /* static curveball_debug_initialized = 0; */
    /* static CB_DEBUG = 0; */

    /* if (! curveball_debug_initialized) { */
    /*     char* dbgenv = PR_GetEnv("DEBUG_CURVEBALL"); */
    /*     if (dbgenv) { */
    /*         CB_DEBUG = atoi(dbgenv); */
    /*     } */
    /*     curveball_debug_initialized = 1; */
    /* } */
    /* if (cb_debug == 0 && CB_DEBUG == 0) return; */

    /* call with NULL prefix to just dump the hex bits, with no
     * decorations
     */
    if (prefix != NULL) {
        printf("\n%s: (len: %d)", prefix, len);
    }

    if (buf == NULL) {
	printf("NULL buf ptr");
    }
    else {
        for (i = 0; i < len; i++) {
            printf("%02x", buf[i]);
        }
    }
    if (prefix != NULL) {
	printf("\n");
    }
    fflush(stdout);
}

/* The goal is to take a key and generate multiple sentinels (and
 * "sentinel label" bits from it.
 *
 * Perhaps the most surprising thing about the following is that the
 * keybuf is not in binary, but in binhex format (this lets us copy the
 * keybuf in from the same sort of ascii-file that python reads it from).
 *
 * The following routine is done with the following bit of python code
 * (from gen_sentinels.py):
 *
 def create_sentinel(mykey, number, time_str=None):
 """
 Given a key, number, and optional time_str, create the corresponding
 sentinel.

 If time_str is not supplied, then it is computed directly by calling
 create_date_hmac_str.
 """

 if time_str == None:
 time_str = create_date_hmac_str()
 # time_str has the format 'YYYY-MO-DA HR', using UTC as the time
 msg = '%s %d' % (time_str, number)
 return hmac.new(mykey, msg, hashlib.sha256).hexdigest()

 * the hexdigest() is a convenience for printing, it will get converted to
 * binary before being used for anything, so we can skip that step.
 *
 * For how to do HMAC, see
 * http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn5.html
 */
SECStatus curveball_generate_sentinel_data(int seed,
	unsigned char *keybuf, int keybuflen,
	unsigned char *sentinel, unsigned char *sentinel_label)
{
    time_t t;
    struct tm *tmp;
    /* +11 is enough room for space + 9-digit number + NULL */
    char time_str[sizeof("YYYY-MM-DD HH")];
    unsigned char hash_input[sizeof(time_str) + 11];
    unsigned char hash_output[CB_SENTINEL_HMAC_BYTES];
    unsigned int hash_output_len = sizeof(hash_output);
    SECStatus rv;
    SECItem param;
    PK11Context *DigestContext;

    CK_MECHANISM_TYPE hmacMech = CKM_SHA256_HMAC;
    SECItem keyItem;
    PK11SlotInfo *slot;
    PK11SymKey *SymKey;

    int i;

    keyItem.type = siBuffer;
    keyItem.data = keybuf;
    keyItem.len = keybuflen;

    slot = PK11_GetBestSlot(hmacMech, NULL);

    SymKey = PK11_ImportSymKey(slot, hmacMech, PK11_OriginUnwrap, CKA_SIGN,
	    &keyItem, NULL);

    t = time(NULL);
    tmp = gmtime(&t);

    if (CB_PER_DAY_SENTINELS) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d", tmp);
    }
    else {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H", tmp);
    }
    PR_snprintf((char*) hash_input, sizeof(hash_input), "%s %d", time_str, seed);

    param.type = siBuffer;
    param.data = NULL;
    param.len = 0;

    DigestContext = PK11_CreateContextBySymKey(hmacMech, CKA_SIGN,
	    SymKey, &param);

    /* FIXME: check rv result */
    rv = PK11_DigestBegin(DigestContext);
    rv = PK11_DigestOp(DigestContext, hash_input, strlen((char*)hash_input));
    rv = PK11_DigestFinal(DigestContext, hash_output, &hash_output_len,
                          sizeof(hash_output));
    /* now, hash_output contains the 'signed digest', and hash_output_len
     * contains the length of the digest
     */

    memmove(sentinel, hash_output, CB_SENTINEL_BYTES);
    memmove(sentinel_label, &hash_output[CB_SENTINEL_BYTES],
	    CB_SENTINEL_LABEL_BYTES);

    return rv;
}

void
curveball_generate_pms_data(sslSocket *ss, unsigned char *random)
{
    /* We construct the premaster secret from SentinelLabel,
     * ServerRandom (including the ServerTimestamp), and
     * ClientRandom.
     */
    unsigned char buffer[SSL3_RANDOM_LENGTH
                         + SSL3_RANDOM_LENGTH
                         + CB_SENTINEL_LABEL_BYTES];
    unsigned char pms_hash[SHA512_LENGTH];
    unsigned int sha_len;
    PK11Context *sha;

    /* SHA512 gives us 512b (64B) of output to squeeze into our 46B of
     * pms->random[]
     */
    memcpy(&buffer[0],
           &ss->ssl3.hs.client_random,
           SSL3_RANDOM_LENGTH);
    memcpy(&buffer[SSL3_RANDOM_LENGTH],
           &ss->ssl3.hs.server_random,
           SSL3_RANDOM_LENGTH);
    memcpy(&buffer[2 * SSL3_RANDOM_LENGTH],
           ss->cbt.sent_sentinel_label,
           CB_SENTINEL_LABEL_BYTES);

    curveball_asciify("CLIENT PREMASTER SECRET INPUT: ",
                      buffer,
                      sizeof(buffer));

    sha = PK11_CreateDigestContext(SEC_OID_SHA512);
    PK11_DigestBegin(sha);
    PK11_DigestOp(sha, buffer, sizeof(buffer));
    PK11_DigestFinal(sha, pms_hash, &sha_len, SHA512_LENGTH);
    PK11_DestroyContext(sha, PR_TRUE);

    memcpy(random, pms_hash, CURVEBALL_PMS_RANDOM_BYTES);

    curveball_asciify("CLIENT PREMASTER SECRET: ",
	    random, CURVEBALL_PMS_RANDOM_BYTES);
}


#define RESPONSE_UNI "HTTP/1.1"

/*
 * Check for dp hello in tls unidirectional
 */
int
curveball_is_dp_hello_uni(sslSocket *ss, sslBuffer *plaintext)
{
    char *responsePtr = strchr(plaintext->buf, RESPONSE_UNI[0]);

    if (CURVEBALL_TUNNEL_TYPE == CURVEBALL_BIDIRECTIONAL_TUNNEL) {
	return 0;
    }

    if ((plaintext->len > sizeof(RESPONSE_UNI)) && responsePtr) {
        for (;
            responsePtr < &plaintext->buf[plaintext->len - sizeof(RESPONSE_UNI)];
            responsePtr++) {

            if (strstr(responsePtr, RESPONSE_UNI)) {
                /* Actual check will occur in ccp_client, so we return 1 here */
                return 1;
            }
        }
    }

    return 0;
}

#define WELCOME_BI "welcome to curveball"

/*
 * Check for dp hello in tls bidirectional
 */
int
curveball_is_dp_hello(sslSocket *ss, sslBuffer *plaintext)
{
    char *welcomePtr = strchr(plaintext->buf, WELCOME_BI[0]);

    if ((plaintext->len > sizeof(WELCOME_BI)) && welcomePtr) {
        for (;
            welcomePtr < &plaintext->buf[plaintext->len - sizeof(WELCOME_BI)];
            welcomePtr++) {
            if (strncmp(welcomePtr, WELCOME_BI, sizeof(WELCOME_BI)) == 0) {
                DEBUGPR(1, (stderr, "**** Got Welcome to curveball ****"));
                return 1;
            }
        }
    }
    DEBUGPR(1, (stderr, "No welcome to curveball, yet"));
    return 0;
}

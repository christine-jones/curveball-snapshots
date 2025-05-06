/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017 and in
 * part by a grant from the United States Department of State.
 * The opinions, findings, and conclusions stated herein are those
 * of the authors and do not necessarily reflect those of the United
 * States Department of State.
 *
 * Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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

/* A prototype Curveball client agent

   It connects to the server, makes an HTTP
   request and waits for the response, which will hopefully come in
   the form of a DP-hello message.  When it gets one of those, it
   opens a listen socket on curveball_agent_port (4435, at the
   moment).  When it receives a connection on that port, it copies
   data from that connection to the DP, and from the DP to that local
   socket.

   client-agent -h host -p port -s sentinel [-c certdb-dir ]

   To test, set up three windows:

   - run "toy_dp -priv priv.pem -pub pub.pem -sess curveball" in one
   - run "client-agent" in another
   - after a bit, run "nc localhost 4435" in the third.  nc should
     print some stuff (sent by toy_dp as test output)
   - what you type to nc should be spat out by toy_dp.
*/

/*
  #include <sys/select.h>
*/
/* It would be nice if there was a __POSIX__ define we could use */
#if __unix__||__APPLE__
#include <libgen.h> /* for basename */
#else
#include <string.h> /* for strrchr */
static char *basename(const char *x)
{
    char *r = strrchr(x, '/');
    return r ? (r + 1) : x;
}
#endif /* __unix__||__APPLE__ */

#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "nspr.h"
#include "prprf.h"
#include "ssl.h"
#include "sslproto.h"

#include <prinit.h>
#include <prmem.h>
#include <prio.h>
#include <pk11func.h>
#include <prtypes.h>
#include <prio.h>
#include <plgetopt.h>
#include <secmod.h>

#include "common.h"
#include "curveball_public.h"
#include "cb_stencil.h"

/* we've fixed the issue that caused all certificates to
 * be rejected; now we can assume that the ones that are
 * rejected really and truly are bad.
 */
#define SERVER_AUTH_BUG_FIXED 1

int exit_on_no_dr = PR_TRUE;

/* TODO: dp does not work with a lot of the standard cipher suites
 * To provoke servers into actually talking on a suite we can handle,
 * don't advertise the ones that we ignore.
 *
 * The fix here is: make the DP work with more cipher suites and also make
 * it fail in a manner that lets the client-agent complete the TLS
 * handshake (instead of hang).
 */
#define CURVEBALL_LIMIT_CIPHER_SUITES yes

#define DEBUGPR  fprintf
static int CB_DEBUG = 0;

#define HTTP_HEADER \
	"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:33.0) " \
	"Gecko/20100101 Firefox/33.0\r\n" \
	"Accept: text/html\r\n" \
	"Accept-Language: en-US,en;q=0.5\r\n" \
	"Accept-Encoding: \r\n" \
	"Connection: keep-alive\r\n\r\n"

#define REQUEST_TEMPLATE_BI \
	"GET / HTTP/1.1\r\nHost: %s\r\n" \
	HTTP_HEADER

#define REQUEST_SUFFIX_TEMPLATE \
	" HTTP/1.1\r\nHost: %s\r\n" \
	HTTP_HEADER

#define REQUEST_TEMPLATE_UNI \
	"GET /ConnectToCurveballaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa " \
	REQUEST_SUFFIX_TEMPLATE

#define HTTPS_PORT (443)
#define DEFAULT_CLIENT_AGENT_PORT	(4435)

static int curveball_agent_port = DEFAULT_CLIENT_AGENT_PORT;

static char *progname = "";

int sentinel_seed = 0;

/* Note that lib/ssl/ssl3con.c has a table of Curveball cipher suites that
 * takes precedence over this one.
 */
PRInt32 cipher_set[] = {
#ifdef CURVEBALL_LIMIT_CIPHER_SUITES
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
#else /* don't limit cipher suites */
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
    SSL_RSA_WITH_RC4_128_SHA,

    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,

    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,

    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,

    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_ECDH_RSA_WITH_RC4_128_SHA,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,

    TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_SEED_CBC_SHA,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    SSL_RSA_WITH_RC4_128_MD5,

    SSL_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

    SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA
#endif /* LIMIT CIPHER SUITES */
};

unsigned char deadbeef[] = {
    '\xde', '\xad', '\xbe', '\xef',
    '\0',   '\0',   '\0',   '\0',
};

unsigned char sentinel_data[CB_SENTINEL_BYTES];

/* This is repeated in CT_DP2.py, in the init for the SrcProtocol class. */
unsigned char aes_hello_key_data[] = {
    '\x05', '\xf4', '\xca', '\x32',
    '\x60', '\x14', '\xf5', '\x66',
    '\x64', '\xc5', '\x04', '\x4b',
    '\xcf', '\x35', '\xf9', '\x32',

    '\xb4', '\x04', '\x57', '\x80',
    '\x34', '\x72', '\x8d', '\xe4',
    '\xc8', '\x04', '\x35', '\xf7',
    '\xbd', '\x77', '\x7f', '\x81'
};

unsigned char aes_iv_data[] = {
    '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0',

    '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0',

    '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0',

    '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0'
};

SECItem aes_hello_key = {
    0,
    aes_hello_key_data,
    sizeof(aes_hello_key_data)
};

SECItem aes_iv = {
    0,
    aes_iv_data,
    sizeof(aes_iv_data)
};

#include <stdio.h>


/*
 *************************************************************************
 * FUNCTION: DEBUG_asciify
 * DESCRIPTION:
 *************************************************************************
 */
static void
DEBUG_asciify(int flag, char *prefix, unsigned char *buf, int len)
{
    int i;

    if (CB_DEBUG == 0) {
	return;
    }

    printf("\n%s: (len: %d)", prefix, len);
    for (i = 0; i < len && i < 80; i++) {
        if (isalpha(buf[i])) {
            printf(" %d", buf[i]);
	}
        else {
            printf("%02x", buf[i]);
	}
    }
    if (len >= 80) {
	printf("...");
    }
    printf("\n");
    fflush(stdout);
}


/*
 *************************************************************************
 * FUNCTION: tunnel
 * DESCRIPTION:
 *              client-sock is a local, regular socket
 *
 *************************************************************************
 */
void tunnel(PRFileDesc *client_sock, PRFileDesc *ssl)
{
    int alive = 1;
    int anyerr = PR_POLL_ERR | PR_POLL_EXCEPT;
    int ii, jj;

    while (alive) {
        int psel;
        PRPollDesc pds[2];
        PRIntervalTime pr_timeout = 5000;

        pds[0].fd = ssl;
        pds[0].in_flags = PR_POLL_READ;
        pds[0].out_flags = 0;

        pds[1].fd = client_sock;
        pds[1].in_flags = PR_POLL_READ;
        pds[1].out_flags = 0;


        psel = PR_Poll(pds, 2, pr_timeout);

        if (psel > 0) {
            int nread;
            char buf[4096];
            char err[128];

	    /* Check for errors, if so, turn off alive */
	    if (alive && (pds[0].out_flags & anyerr)) {
		PR_snprintf(err, sizeof(err),
			"%s: error condition on ssl;", progname);
		alive = 0;
		break;
	    }

	    if (alive && (pds[1].out_flags & anyerr)) {
		PR_snprintf(err, sizeof(err),
			"%s: error condition on client;", progname);
		alive = 0;
		break;
	    }

            /* Don't even try this if we've just turned off "alive" */
            if (alive && (pds[0].out_flags & PR_POLL_READ)) {

            	/********************
                 * ssl -> client
                 ********************/

            	/* Read from ssl */
            	nread = PR_Read(ssl, buf, sizeof(buf));
            	/*
            	printf("ssl buf length is %d\n", nread);
            	for (ii=0; ii<nread; ii++) {
            		 printf("%c", buf[ii]);
          		}
            	printf("\n");
            	*/

            	if (nread < 0) {
		    PR_snprintf(err, sizeof(err), "%s: SSL read error;",
			    progname);
		    PR_error(err);
		    alive = 0;

            		/* Write to client */
            	} else if (nread > 0) {
		    if (PR_Write(client_sock, buf, nread) < 0) {
			PR_snprintf(err, sizeof(err), "%s: SSL write error",
				progname);
			PR_error(err);
			alive = 0;
		    }

            		/* DP is gone */
            	} else if (nread == 0) {
		    fprintf(stderr, "DP gone\n");
		    alive = 0;
            	}
            }

            /* Don't even try this if we've just turned off "alive" */
            if (alive && (pds[1].out_flags & PR_POLL_READ)) {

            	/*****************
            	 * client -> ssl
            	 *****************/

            	/* Read from client */
            	nread = PR_Read(client_sock, buf, sizeof(buf));

            	/*
            	printf("client_sock buf length is %d\n", nread);
            	for (jj=0; jj<nread; jj++) {
            		 printf("%c", buf[jj]);
            	}
            	printf("\n");
            	 */

            	if (nread < 0) {
		    PR_snprintf(err, sizeof(err),
			    "%s: Error reading from client;", progname);
		    PR_error(err);
		    alive = 0;

            		/* Write to ssl */
            	} else if (nread > 0) {
		    if (PR_Write(ssl, buf, nread) < 0) {
			PR_snprintf(err, sizeof(err),
				"%s: SSL write error", progname);
			PR_error(err);
			alive = 0;
		    }

            		/* tunnel client is gone */
            	} else if (nread == 0) {
		    fprintf(stderr, "tunnel client gone\n");
		    alive = 0;
            	}
            }
        }
    }

    /* this might fail; client_sock might already be gone */
    PR_Shutdown(client_sock, PR_SHUTDOWN_BOTH);
    PR_Close(client_sock);
    return;
}


/*
 *************************************************************************
 * FUNCTION: curveball_tunnel_server
 * DESCRIPTION:
 *
 *************************************************************************
 */
static void curveball_tunnel_server(PRFileDesc* ssl)
{
    PRSocketOptionData sockopt;
    PRFileDesc *client_sock;
    PRFileDesc *listen_sock = PR_NewTCPSocket();
    PRNetAddr any_address;
    PRNetAddr client_address;
    PRStatus status;

    PR_InitializeNetAddr(PR_IpAddrAny, curveball_agent_port, &any_address);

    sockopt.option = PR_SockOpt_Reuseaddr;
    sockopt.value.reuse_addr = PR_TRUE;
    PR_SetSocketOption(listen_sock, &sockopt);

    status = PR_Bind(listen_sock, &any_address);
    if (status != PR_SUCCESS) {
        berr_exit("Cannot bind the local endpoint socket");
    }

    status = PR_Listen(listen_sock, 10);
    if (status != PR_SUCCESS) {
        berr_exit("Cannot listen to the local endpoint socket");
    }

    client_sock = PR_Accept(listen_sock, &client_address,
	    PR_INTERVAL_NO_TIMEOUT);
    if (client_sock == NULL) {
        berr_exit("PR_Accept failed; exiting");
    }
    /* if this weren't single-streamed, we would fork here, but the
     * client-agent serves only one customer at a time
     */
    if (CB_DEBUG) {
        fprintf(stderr, "Accepting tunnel connection\n");
    }

    tunnel(client_sock, ssl);
}


/*
 *************************************************************************
 * FUNCTION: http_request
 * DESCRIPTION:
 *
 *************************************************************************
 */
static int http_request(PRFileDesc *ssl, char *hostname, PRUint16 port,
		char *request_template, unsigned char *stencil_key)
{
    int curveball_mode = 0;
    char request[2 * BUFSIZZ];
    char buf[2 * BUFSIZZ];
    int r;
    int len, request_len;
    int i;

    /* Now construct our HTTP request */
    request_len = PL_strlen(request_template) + PL_strlen(hostname) + 6;
    if (request_len > sizeof(request)) {
	err_exit("Request length too long");
    }
    PR_snprintf(request, request_len, request_template, hostname);

    /* Find the exact request_len */
    request_len = PL_strlen(request);

    if (CURVEBALL_TUNNEL_TYPE == CURVEBALL_BIDIRECTIONAL_TUNNEL) {

	if (PR_Write(ssl, request, request_len) < 0) {
	    const PRErrorCode err = PR_GetError();
	    fprintf(stderr, "PR_Write error %d: %s\n",
		    err, PR_ErrorToName(err));
	    berr_exit("Failed to send initial request");
	}
    }
    else {
	unsigned int request_suffix_len =
		strlen(REQUEST_SUFFIX_TEMPLATE) + strlen(hostname) + 10;
	unsigned char *request_suffix = malloc(request_suffix_len);
	int rc;

	if (request_suffix == NULL) {
	    berr_exit("Failed to allocate request string");
	}
	PR_snprintf(request_suffix, request_suffix_len,
		REQUEST_SUFFIX_TEMPLATE, hostname);

	/* In unidirectional we won't know there's a DR in the
	 * path until AFTER we send the stencil.  We send
	 * the stencil in the hope that a DR will answer.
	 *
	 * The enc_key should be part of the sentinel_label
	 * that has not been sent in the clear (preferably
	 * not used at all).
	 */
	rc = cb_stencil_send(ssl, NULL,
		stencil_key, 2 * CB_STENCIL_KEY_BYTES,
		request_suffix);
	if (rc != 0) {
	    /* TODO: we should send something, even if it's
	     * bogus, and then wait for the response before
	     * exiting.  It looks strange to open a TLS
	     * connection and then close it without sending
	     * anything whatsoever.
	     */
	    berr_exit("Failed to create and/or send stencil");
	}
    }

    /* Now read the server's response, assuming
       that it's terminated by a close */
    r = 1;
    while (r > 0) {

        /* we expect this read to fail, because of the cipher
         * change, but not be zero.
         */
        r = PR_Read(ssl, buf, BUFSIZZ);
        if (r == 0) {
            berr_exit("SSL connection: closed unexpectedly");
        }

        if (curveball_decoy_proxy_in_path(ssl)) {
            if (curveball_mode == 0) {
                curveball_mode = 1;
            }
            if (CURVEBALL_TUNNEL_TYPE == CURVEBALL_UNIDIRECTIONAL_TUNNEL) {
                if (PR_Write(ssl, request, request_len) < 0) {
                    const PRErrorCode err = PR_GetError();
                    fprintf(stderr, "PR_Write error %d: %s\n",
                            err, PR_ErrorToName(err));
                    berr_exit("Failed to send initial request");
                }
            }
            /* We found a DP, that first message was just the DP
			   saying hello, let's wait for the welcome message */
            curveball_tunnel_server(ssl);
            return -1;

        }
	else if (exit_on_no_dr) {
        	printf("No DR on path\n");
        	exit(4);
        }

        if (r < 0) {
            berr_exit("SSL read problem");
	}
        else if (r > 0) {
            len = r;
            fwrite(buf, 1, len, stdout);
        }
    }

    return (0);
}

/*
 *************************************************************************
 * FUNCTION: get_password
 * DESCRIPTION:
 *
 *************************************************************************
 */
char *get_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    DEBUGPR(stderr, "get_password returning \"curveball\"\n");
    return "curveball";
}


/*
 *************************************************************************
 * FUNCTION: ApproveCertificate
 * DESCRIPTION:
 *
 *   A dummy check on the certificate --- using it until I figure out what
 *   is causing this program to reject all certificates at the moment.
 *
 *************************************************************************
 */
#ifndef SERVER_AUTH_BUG_FIXED
SECStatus ApproveCertificate(void *arg, PRFileDesc *fd, PRBool checkSig,
	PRBool isServer)
{
    if (CB_DEBUG) {
	DEBUGPR(stderr, "%s: skipping cert check, just saying 'Approved'\n",
		progname);
    }
    return SECSuccess;
}
#endif /* SERVER_AUTH_BUG_FIXED */

/*
 *************************************************************************
 * FUNCTION: BadCertHandler
 * DESCRIPTION:
 *
 *************************************************************************
 */
SECStatus BadCertHandler(void *arg, PRFileDesc *fd)
{
    CERTCertificate *cert;
    PRErrorCode err;
    const char *errname;

    err = PR_GetError();
    errname = PR_ErrorToName(err);

    fprintf(stderr, "Error: server certificate rejected: code %d (%s)\n",
	    err, errname);

    if (NULL != (cert = SSL_PeerCertificate(fd))) {
        DEBUG_asciify(1, "peer cert", cert, sizeof(*cert));
        CERT_DestroyCertificate(cert);
    }
    else {
        fprintf(stderr, "Can't get peer certificate\n");
    }

    return SECFailure;
}

/*
 *************************************************************************
 * FUNCTION: usage_exit
 * DESCRIPTION:
 *************************************************************************
 */
void usage_exit(char *msg)
{
    fprintf(stderr, "%s: %s\n", progname, msg);
    fprintf(stderr, "usage: %s -h host -p port [-s sentinel] [-d] [options]\n",
	    progname);
    fprintf(stderr, "\n\n");
    fprintf(stderr, "    -A port   The port this agent listens on"
	    " (on localhost) [default=%d]\n", DEFAULT_CLIENT_AGENT_PORT);
    fprintf(stderr, "    -c path   The configuration directory\n");
    fprintf(stderr, "    -d        Use the debugging sentinel "
	    "(aka \"deadbeef\")\n");
    fprintf(stderr, "    -h host   The decoy host (name or IPv4 address)\n");
    fprintf(stderr, "    -p port   The port on the decoy host\n");
    fprintf(stderr, "    -s sent   The sentinel/sentinel label to use\n");

    fprintf(stderr, "\n"
	    "If the -d option is given, then the debugging sentinel\n"
	    "is used, and the -s option is ignored.\n"
	    "\n"
	    "If the -s option is given (but not -d), then the given\n"
	    "sentinel is used.\n"
	    "\n"
	    "Either the -d or the -s option must be given.\n"
	    "\n");

    fprintf(stderr, "\n");

    exit(1);
}

/*
 *************************************************************************
 * FUNCTION: hex2binary
 * DESCRIPTION:
 *************************************************************************
 */
static void hex2binary(unsigned char *out_binary, unsigned char *in_hex,
	size_t len)
{
    size_t i;
    char buf[3];

    for (i = 0; i < len; i++) {
	buf[0] = in_hex[2 * i];
	buf[1] = in_hex[(2 * i) + 1];
	buf[2] = '\0';

	out_binary[i] = strtol(buf, NULL, 16);
    }

    return;
}

/*
 *************************************************************************
 * FUNCTION: main
 * DESCRIPTION:
 *
 *************************************************************************
 */
int main(int argc, char **argv)
{
    extern char *optarg;
    SECStatus secstat;
    PRStatus r;
    char *certdb = "certdb";
    PRFileDesc *sock;
    PRNetAddr na_server;
    PRHostEnt hp;
    PRUint16 port = HTTPS_PORT;
    char netdbbuf[PR_NETDB_BUF_SIZE];
    char err[256];
    char *hostname = NULL;
    int i;
    PLOptState *optstate;
    int use_deadbeef = 0;
    char *sentinel_hex = NULL;
    unsigned char sentinel[CB_SENTINEL_BYTES];
    unsigned char sentinel_label[CB_SENTINEL_LABEL_BYTES];
    unsigned char stencil_key[2 * 2 * CB_STENCIL_KEY_BYTES];
    SECStatus rv;
    char *src_addr_txt = NULL;

    /* Assume bidirectional request by default */
    char *request_template = REQUEST_TEMPLATE_BI;

    progname = basename(argv[0]);

    {
        char *dbgenv = PR_GetEnv("DEBUG_CURVEBALL");
        if (dbgenv) {
            CB_DEBUG = atoi(dbgenv);
        }
    }
    {
        char *deadenv = PR_GetEnv("USE_DEADBEEF");
        if (deadenv) {
            use_deadbeef = atoi(deadenv);
        }
    }
    {
        char *curveball_enable_envar = getenv("CURVEBALL_ENABLE");
        int level = 100;        /* safely beyond all levels */

        if (curveball_enable_envar) {
            level = atoi(curveball_enable_envar);
	}

        curveball_enable(level);
        if (CB_DEBUG) {
	    fprintf(stderr, "%s: Curveball enabled at level %d\n",
		    progname, level);
	}
    }
    {
        char *env_exit_on_no_dr = PR_GetEnv("CB_CLIENT_NO_DR");
        if (env_exit_on_no_dr) {
            exit_on_no_dr = atoi(env_exit_on_no_dr);
        }
    }

    if (CB_DEBUG) {
	fprintf(stderr, "%s: Curveball debugging enabled\n", progname);
    }

    optstate = PL_CreateOptState(argc, argv, "A:c:dh:i:k:p:s:S:u");
    while (PL_GetNextOpt(optstate) == PL_OPT_OK) {
	switch (optstate->option) {
	    case 'A':
		if (!(curveball_agent_port = (PRUint16) atoi(optstate->value))) {
		    err_exit("Bogus port specified");
		}
		break;
	    case 'c':
		if (!(certdb = strdup(optstate->value))) {
		    err_exit("Out of memory");
		}
		break;
	    case 'd':
		use_deadbeef = 1;
		break;
	    case 'h':
		if (!(hostname = strdup(optstate->value))) {
		    err_exit("Out of memory");
		}
		break;
	    case 'p':
		if (!(port = (PRUint16) atoi(optstate->value))) {
		    err_exit("Bogus port specified");
		}
		break;
	    case 's': {
		size_t sentinel_hex_len = 2
			* (CB_SENTINEL_LABEL_BYTES + CB_SENTINEL_BYTES);
		char *hex_chars = "0123456789abcdefABCDEF";

		if (!(sentinel_hex = strdup(optstate->value))) {
		    err_exit("Out of memory");
		}

		if (strlen(sentinel_hex) != sentinel_hex_len) {
		    fprintf(stderr, "Sentinel must be %u hex digits\n",
			    sentinel_hex_len);
		    err_exit("Bad sentinel length");
		}

		if (strspn(sentinel_hex, hex_chars) != sentinel_hex_len) {
		    fprintf(stderr, "Sentinel must be %u hex digits\n",
			    sentinel_hex_len);
		    err_exit("Sentinel has non-hex digits in it");
		}
		break;
	    }
	    case 'S': {
		src_addr_txt = strdup(optstate->value);
		break;
	    }

	    case 'u':
		request_template = REQUEST_TEMPLATE_UNI;
		CURVEBALL_TUNNEL_TYPE = CURVEBALL_UNIDIRECTIONAL_TUNNEL;
		break;
	}
    }

    PL_DestroyOptState(optstate);

    if ((sentinel_hex == NULL) && !use_deadbeef) {
	usage_exit("either -s or -d must be specified");
    }

    if (hostname == NULL) {
        usage_exit("hostname unspecified");
    }

    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    PR_STDIO_INIT();

    PK11_SetPasswordFunc(get_password);

    secstat = NSS_Init(certdb);

    if (secstat != SECSuccess) {
        int len = PR_GetErrorTextLength();
        char *errtext = PR_Malloc(256+len);

        if (errtext == NULL) {
            PR_snprintf(err, sizeof(err),
		    "%s: NSS_Init(%s) failed; errcode %d; (Can't allocate storage for %d bytes of error text)",
		    progname, certdb, PR_GetError(), len);
        } else {
            int errlen = PR_GetErrorText(errtext);
            char *errt = "(unknown error)";
            if (errlen)
                errt = errtext;

            PR_snprintf(err, sizeof(err), "%s: NSS_Init(%s) failed; %s",
		    progname, certdb, errt);

            free(errtext);
        }
        berr_exit(err);
    }

    /* Initialize the trusted certificate store. */
    {
	SECMODModule *module;
	/* this spec is OK for Linux and Android, but not WINNT and DARWIN.
	 * See below.
	 */
	char *module_name = "library=libnssckbi.so name=\"Root Certs\"";

#ifdef WINNT
	module_name = "library=nssckbi.dll name=\"Root Certs\"";
#endif /* WINNT */

#ifdef DARWIN
	/* This is a foul hack, but it appears to be necessary on Darwin
	 * because of the security restrictions on using DYLD_ and
	 * LD_LIBRARY_PATH for sudo'd programs.  We can't let the system
	 * search for libnssckbi.dylib; we need to tell it exactly where
	 * it is.
	 *
	 * The returned path from PR_GetLibraryFilePathname returns the
	 * name of the executable (even though we're not really statically
	 * linked).  By convention, we install the libraries in the same
	 * directory as the executable because of a problem on Windows,
	 * so we use the directory where the executable lives as the
	 * prefix of the library path.
	 *
	 * It's easy to imagine this breaking.  There's probably a better
	 * way.
	 */
	{
	    char *my_path;
	    char *last_slash;
	    size_t pathlen;
	    char *module_tmplt;

	    module_tmplt = "library=%s/libnssckbi.dylib name=\"Root Certs\"";
	    my_path = PR_GetLibraryFilePathname("", (PRFuncPtr) NSS_Init);
	    pathlen = strlen(module_tmplt) + strlen(my_path);
	    module_name = PR_Malloc(pathlen);

	    if (module_name == NULL) {
		fprintf(stderr, "Error: PR_Malloc(%lu) failed\n", pathlen);
		exit(11);
	    }

	    last_slash = strrchr(my_path, '/');
	    if (last_slash == NULL) {
		fprintf(stderr, "Error: no directory component in [%s]\n",
			my_path);
		exit(12);
	    }
	    *last_slash = '\0';

	    PR_snprintf(module_name, pathlen, module_tmplt, my_path);
	}
#endif /* DARWIN */

	module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
	if ((module == NULL) || !module->loaded) {
	    const PRErrorCode err = PR_GetError();

	    fprintf(stderr, "Error: NSPR error code %d: %s\n",
		    err, PR_ErrorToName(err));
	    fprintf(stderr, "Error: cannot load module [%s]\n", module_name);
	    exit(1);
	}
    }

    if (use_deadbeef) {
	fprintf(stderr, "%s: Using default sentinel\n", progname);
	memcpy(stencil_key, deadbeef, sizeof(deadbeef));
	memcpy(sentinel, deadbeef, sizeof(deadbeef));
	memset(sentinel_label, '\0', sizeof(sentinel_label));
	memcpy(sentinel_label, deadbeef, sizeof(deadbeef));
    }
    else if (sentinel_hex != NULL) {
	fprintf(stderr, "%s: using sentinel %s\n", progname, sentinel_hex);
	memcpy(stencil_key, sentinel_hex + (4 * sizeof(sentinel)),
		sizeof(stencil_key));
	hex2binary(sentinel, sentinel_hex, sizeof(sentinel));
	hex2binary(sentinel_label, sentinel_hex + (2 * sizeof(sentinel)),
			sizeof(sentinel_label));
    }

    if (CB_DEBUG) {
        curveball_asciify("sentinel_label: ",
		sentinel_label, sizeof(sentinel_label));
    }

    /* Now, copy bytes from the sentinel label into the aes_hello_key and
     * aes_iv data
     */
    memcpy(sentinel_data, sentinel, sizeof(sentinel_data));
    /* sentinel labels are only 24B long, instead of the 32B we need */
    memset(aes_hello_key_data, 0, sizeof(aes_hello_key_data));
    memcpy(aes_hello_key_data, sentinel_label, sizeof(sentinel_label));

    if (! curveball_set_sentinel(sentinel_data)) {
        berr_exit("Can't set sentinel key");
    }
    if (! curveball_set_sentinel_label(sentinel_label)) {
        berr_exit("Can't set sentinel label  key");
    }
    if (! curveball_set_curveball_hello_key(&aes_hello_key)) {
        berr_exit("Can't set AES key");
    }
    if (! curveball_set_curveball_hello_iv(&aes_iv)) {
        berr_exit("Can't set AES IV");
    }

    NSS_SetDomesticPolicy();
    /* XXX:Fixme
     * May want to call SSL_CipherPolicySet for some of the other
     * cipher suites --- see
     * http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1067601
     * As it stands we don't have all the cipher suites that we observe
     * Firefox using.
     */

    /* TODO: at this point, we do NOT we use the Curveball
     * cert for anything other than internal testing, but eventually
     * we will need it to check that the signature on the "welcome to
     * curveball" message is correct.
     */
    if (!curveball_cert("curveball", "curveball")) {
        fprintf(stderr, "%s: Can't get curveball-certificate info: %s\n",
		progname,
                curveball_error);
        exit(10);
    }

    r = PR_GetHostByName(hostname, netdbbuf, PR_NETDB_BUF_SIZE, &hp);
    if (r) {
        PR_snprintf(err, sizeof(err), "%s: Host name lookup failed for %s",
		progname, hostname);
        berr_exit(err);
    }

    PR_EnumerateHostEnt(0, &hp, 0, &na_server);
    PR_InitializeNetAddr(PR_IpAddrNull, port, &na_server);

    sock = PR_NewTCPSocket();

    if (src_addr_txt) {
	PRNetAddr src_addr;
	PRHostEnt src_addr_hp;
	PRStatus status;

	r = PR_GetHostByName(src_addr_txt, netdbbuf, PR_NETDB_BUF_SIZE,
		&src_addr_hp);
	if (r) {
	    PR_snprintf(err, sizeof(err), "%s: Host name lookup failed for %s",
		    progname, src_addr_txt);
	    berr_exit(err);
	}

	PR_EnumerateHostEnt(0, &src_addr_hp, 0, &src_addr);
	PR_InitializeNetAddr(PR_IpAddrNull, 0, &src_addr);

	status = PR_Bind(sock, &src_addr);
	if (status != PR_SUCCESS) {
	    berr_exit("Cannot bind the src addr of the connection socket");
	}
    }

    if (NULL == SSL_ImportFD(NULL, sock)) {
        PR_snprintf(err, sizeof(err), "%s: Can't create SSL socket", progname);
        berr_exit(err);
    }

    /* The following two options appear to be the ones that Firefox uses
     */
    r = SSL_OptionSet(sock, SSL_ENABLE_TLS, PR_TRUE);
    if (r != SECSuccess) {
        PR_snprintf(err, sizeof(err), "%s: Can't SSL_ENABLE_TLS", progname);
        berr_exit(err);
    }

    r = SSL_OptionSet(sock, SSL_ENABLE_SSL2, PR_FALSE);
    r = SSL_OptionSet(sock, SSL_ENABLE_SSL3, PR_FALSE);

    r = SSL_OptionSet(sock, SSL_V2_COMPATIBLE_HELLO, PR_FALSE);
    if (r != SECSuccess) {
        PR_snprintf(err, sizeof(err),
		"%s: Can't disable SSL_V2_COMPATIBLE_HELLO", progname);
        berr_exit(err);
    }

    /* We would like to set up the ciphers that Firefox uses, too.
     * See the note about SSL_CipherPolicySet, above.
     */
    for (i = 0; i < sizeof(cipher_set) / sizeof(cipher_set[0]); i++) {
        r = SSL_CipherPrefSet(sock, cipher_set[i], PR_TRUE);
        if (r != SECSuccess) {
            PR_snprintf(err, sizeof(err), "%s: Can't enable cipher %d(0x%x)",
                        progname, cipher_set[i], cipher_set[i]);
            if (CB_DEBUG) {
                fprintf(stderr, "%s\n", err);
            }
            /* berr_exit(err); */
        }
        else {
            PR_snprintf(err, sizeof(err), "%s: Enabled cipher %d(0x%x)",
                        progname, cipher_set[i], cipher_set[i]);
            if (CB_DEBUG) {
                fprintf(stderr, "%s\n", err);
            }
        }
    }

#ifndef SERVER_AUTH_BUG_FIXED
    SSL_AuthCertificateHook(sock, ApproveCertificate, (void *) NULL);
#else
    SSL_BadCertHook(sock, BadCertHandler, (void *) NULL);
#endif /* SERVER_AUTH_BUG_FIXED */

    r = PR_Connect(sock, &na_server, PR_SecondsToInterval(5));
    if (r == PR_FAILURE) {
        PR_snprintf(err, sizeof(err), "%s: Can't connect", progname);
        berr_exit(err);
    }

    /* it *says* URL, but this name is misleading!  It must be the
     * domainname of the host.
     */
    if (SSL_SetURL(sock, hostname)) {
	PR_snprintf(err, sizeof(err), "Can't create SSL_SetURL(%s)", hostname);
	berr_exit(err);
    }
    if (SSL_SetPKCS11PinArg(sock, NULL)) {
	PR_snprintf(err, sizeof(err), "Can't create set pin");
	berr_exit(err);
    }

    if (CB_DEBUG) {
        fprintf(stdout,"Connected to %s:%d\n", hostname, port);
    }

    http_request(sock, hostname, port, request_template, stencil_key);

    if (CB_DEBUG) {
        fprintf(stderr, "%s: sentinel seed was %d\n", progname, sentinel_seed);
    }

    /* Shutdown the socket */
    PR_Shutdown(sock, PR_SHUTDOWN_BOTH);

    exit(0);
}

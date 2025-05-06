#ifndef _CBCHOOSER_H_
#define _CBCHOOSER_H_

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

#define CBCHOOSER_ROOT_ENV "CBCHOOSER_ROOTDIR"
#define CBCHOOSER_MODE_ENV "CBCHOOSER_MODE"
#define CBCHOOSER_DEBUG_ENV "CBCHOOSER_DEBUG"

#define CBCHOOSER_REQ_SUBDIR "req"
#define CBCHOOSER_RES_SUBDIR "res"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  CBCHOOSER_UNCONFIGURED = 0, 
  CBCHOOSER_CONFIGURED = 1, 
  CBCHOOSER_CONF_FAILED = 2
} cbchooser_status_t;

typedef enum {
  CBCHOOSER_NEVER_PROBE = 1,
  CBCHOOSER_ALWAYS_PROBE = 2,
  CBCHOOSER_USE_CRITERIA = 3
} cbchooser_mode_t;

typedef enum {
  CBCHOOSER_SOCK_STREAM = 1,
  CBCHOOSER_SOCK_DGRAM = 2
} cbchooser_proto_t;

/*
 * The routines that read the state created externally use the file
 * system as a database.  This is generally icky, but Good Enough for
 * what we need to do here, and very easy to visualize.
 */

typedef struct {
    unsigned int num_entries;
    const char *req_dir;
    const char *res_dir;
} cbchooser_config_t;

typedef struct {
    PRUint32 ipv4_addr;
    PRUint32 maskwidth;
    PRUint16 des_port;
    int proto;
    int op;
    int delay;
    PRUint64 seqno;
} cbchooser_record_t;

/*
 * These functions are used by wrappers of third-party network connection
 * libraries (i.e., NSS or OpenSSL) to control when to "probe" for a DR
 * and when to establish an ordinary, non-Curveball connection.  The
 * decisions about which connections to probe are, for the most part,
 * made elsewhere.
 *
 * For these functions:
 * url - a character pointer to a URL (may be NULL)
 * 
 * addr - a 32-bit IP address, in native format (the first octet becomes the
 * high-order bits, so 10.11.12.13 would be 0x0a0b0c0d.
 *
 * des_port - the destination port of the connection
 *
 * proto - SOCK_STREAM or SOCK_DGRAM (tcp and udp, respectively)
 *
 * result - non-zero if a probe was attempted and successful, zero if a
 * probe was attempted unsuccessfully.
 *
 * The url is passed in because the decision-making process (whether to
 * test a connection for a DR or not) may be able to use the URL to make a
 * better decision.
 *
 * NOTE: these functions are NOT thread-safe.  If there is any possibility
 * that these functions will be called by multiple threads concurrently, the
 * calls must be serialized (typically by protecting them with a lock).
 * Only one call to any of these functions should be running at any moment.
 *
 * ENVIRONMENT:
 *
 * The configuration of cbchooser is done via environment variables.
 *
 * CBCHOOSER_ROOTDIR - a path (relative or absolute) to a directory that
 * cbchooser can use for scratch space.  This directory must not be used
 * for any other purpose, and it must exist before cbchooser is
 * configured.  If this environment variable is not set, then the
 * library will fail to configure.
 *
 * CBCHOOSER_MODE - set to an integer selected from the cbchooser_mode_t
 * enum (see the definition above for the selection of values).
 *
 * FUNCTIONS:
 *
 * cbchooser_test() returns non-zero if a new connection to the given
 * addr, port, via the given proto, should be probed, zero if not.  Note
 * that the results of this function must *not* be cached because the
 * return value for successive calls with the same parameters may be
 * different,  Similarly, it should be called before *all* connections.
 * This is because cbchooser_test() maintains internal state and is
 * controlled by external state, so there is more context than meets the
 * eye.  (For example, the cbchooser might "know" that there are going
 * to be three connections established to the same destination address,
 * and the second one is the one that should be probed, but never the
 * first).
 *
 * cbchooser_result() records whether an attempt to probe the given
 * addr/port/proto succeeded (result is non-zero) or failed (result is
 * zero).
 *
 * cbchooser_status() is a convenience function that tells the caller
 * whether the internal state of cbchooser can be or has been successfully
 * configured.   If the state is unconfigured, then cbchooser_status()
 * will attempt to configure the status, and this is guaranteed to
 * either succeed (changing the state to _CONFIGURED) or fail (changing
 * the status to _CONF_FAILED).  If the state is not configured, then
 * cbchooser_test() * will always return 0, causing the system to
 * behave as it would without any probes whatsoever.
 *
 * EXAMPLE PSEUDOCODE:
 *
 * To create the current TLS tunnels, the top-level code looks like:
 *
 * if (CurveballEnabled) {
 *   ct = makeTlsCovertTunnel(addr);
 *   if (ct == NULL) {
 *     HandleError;
 *   }
 *   return ct;
 * }
 * else {
 *   tls = makeTlsConnection(addr);
 *   return tls;
 * }
 *
 * Substitute for the first three lines:
 *
 * if (CurveballEnabled && cbchooser_test(addr, 443, SOCK_STREAM)) {
 *   ct = makeTlsCovertTunnel(addr);
 *   cbchooser_test(url, addr, 443, SOCK_STREAM, ct != NULL);
 *   if (ct == NULL) {
 *   ...
 */

int cbchooser_test(const char* url, PRUint32 addr, PRUint16 des_port, int proto);
int cbchooser_result(const char* url, PRUint32 addr, PRUint16 des_port, cbchooser_proto_t proto, int result);

/*
 * Check whether cbchooser can be configured.
 */
cbchooser_status_t cbchooser_status(void);
/*
 * Return a pointer to the config structure
 */
cbchooser_config_t* cbchooser_config_get(void);

/*
 * Set the cbchooser mode.  Returns the previous mode.
 *
 * The default mode, when the system starts, is set during configuration
 * to the numeric value of the environment variable "CBCHOOSER_MODE".
 * If this environment variable is not set, then the default is to set
 * it to the numeric value of CBCHOOSER_USE_CRITERIA (to enable cbchooser).
 *
 * If given a bogus mode, makes no change to the mode and returns the
 * current mode.
 */
cbchooser_mode_t cbchooser_mode(cbchooser_mode_t new_mode);

/*
 * Turn debugging diagnostics on (if debug != 0) or off (if debug == 0).
 */
int cbchooser_debug(int debug);

char *CB_GetEnv(const char *param_name);

#ifdef __cplusplus
};
#endif

#endif /* _CBCHOOSER_H_ */

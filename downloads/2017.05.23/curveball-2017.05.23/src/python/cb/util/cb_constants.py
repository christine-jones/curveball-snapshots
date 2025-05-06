#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import os.path

"""
TODO: Need to make sure that information about DP is not
      inadvertently leaked in constants file, since constants
      file will also be used by client.

      DP-specific contants should be put in cb_constants_dp.py
"""


"""
Client Handshake and Covert Tunnel States
"""

STATE_0   = 'State 0:  request tunnel type'
STATE_1   = 'State 1:  send sentinel'
STATE_3   = 'State 3:  send premaster'
STATE_5   = 'State 5:  check for welcome'
STATE_5_5 = 'State 5.5:  ready, request sent'
STATE_7   = 'State 7:  ready, response received'

STATE_0_UNI   = 'State 0:  request tunnel type'
STATE_1_UNI   = 'State 1:  send sentinel'
STATE_3_UNI   = 'State 3:  check for welcome'
STATE_3_5_UNI = 'State 3.5:  ready, request sent'
STATE_5_UNI   = 'State 5:  ready, response received'


"""
Sentinel constants
"""
SENTINEL_BYTE_LEN     = 16
SENTINEL_HEX_LEN      = 32
FULL_SENTINEL_HEX_LEN = 64
SENTINEL_DEADBEEF     = 'DEADBEEF00000000'
FULL_SENTINEL_DEADBEEF = '05f4ca326014f56664c5044bcf35f932b404578034728de4c80435f7bd777f81'


"""
Constants for information used to create
final Client and DP keys
"""
NONCE_CLIENT_BYTE_LEN = 16
NONCE_CLIENT_HEX_LEN  = NONCE_CLIENT_BYTE_LEN *2
NONCE_DP_BYTE_LEN     = 16
SIGNATURE_BYTE_LEN    = 128
PREMASTER_BYTE_LEN    = 32
SALT_BYTE_LEN         = 16
ENCRYPT_SALT_NONCE_BYTE_LEN = 59
ENCRYPT_SALT_NONCE_HEX_LEN  = ENCRYPT_SALT_NONCE_BYTE_LEN + ENCRYPT_SALT_NONCE_BYTE_LEN
"""
Key block constants for when computing final
client and dp keys. Key block is in hex, so
these constants are hex
"""
KEY_HEX_LEN           = 32
IV_HEX_LEN            = 32
MAC_HEX_LEN           = 32
TEMP_KEY_HEX_LEN      = 10


"""
HMAC constants
"""
HASH_BYTE_LEN = 32

"""
Sequence Numbers
"""
SEQ_NUM_RAND_BYTE_LEN = 4

"""
Other encryption constants
"""
ENCRYPTION_BLOCK_LEN = 16


"""
Multi-flow constants
"""
DECOUPLED_ID_BYTE_LEN = SENTINEL_BYTE_LEN + \
                        NONCE_CLIENT_BYTE_LEN

DECOUPLED_ID_HEX_LEN = DECOUPLED_ID_BYTE_LEN + \
                       DECOUPLED_ID_BYTE_LEN

"""
Public key constants
"""
DP_PUB_KEY_NAME = "pub.pem"
# Where are the key certs relative to the client executable?

# For windows only:
RELATIVE_PATH_WIN_PUB_KEY = os.path.join('auth', 'certs')

# This is the correct path for all known non-windowns installs:
RELATIVE_PATH_PUB_KEY = os.path.join('..', 'auth', 'certs')

# TODO: this shouldn't be used.
RELATIVE_PATH_BUILD_PUB_KEY = os.path.join('..', 'build', 'auth', 'certs')


"""
Private key constants

Note: most private key constants are in cb_constants_dp.py
"""
SIGNATURE_DP_PRIV_KEY_BYTE_LEN = 128

SIGNATURE_DP_PRIV_KEY_HEX_LEN = SIGNATURE_DP_PRIV_KEY_BYTE_LEN + \
                                SIGNATURE_DP_PRIV_KEY_BYTE_LEN


"""
Cookie constants
"""
COOKIE_NAME = 'SESSIONID'
TUNNEL_COOKIE_NAME = 'ID'
COOKIE_NAME_LEN = len( COOKIE_NAME )
COOKIE_SEPARATOR = '; '

# Note that this value is pretty arbitrary
# Just don't want to waste too much space with the domain
MAX_SET_COOKIE_DOMAIN_LEN = 36

"""
Tunnel type constants
"""
UNKNOWN_TUNNEL = "0: unknown tunnel"
HTTP_BI_TUNNEL = "1: bidirectional http tunnel"
HTTP_UNI_TUNNEL = "2: unidirectional http tunnel"
TLS_BI_TUNNEL = "3: bidirectional tls tunnel"
TLS_UNI_TUNNEL = "4: unidirectional tls tunnel"
BITTORENT_BI_TUNNEL = "5: bidirectional bittorent tunnel"
BITTORENT_UNI_TUNNEL = "6: unidirectional bittorent tunnel"
CREATE_HTTP_BI_TUNNEL = "7: bidirectional http tunnel to create"
CREATE_HTTP_UNI_TUNNEL = "8: unidirectional http tunnel to create"
CREATE_TLS_BI_TUNNEL = "9: bidirectional tls tunnel to create"
CREATE_TLS_UNI_TUNNEL = "10: unidirectional tls tunnel to create"

"""
HTTP constants
"""
END_LINE = '\r\n'
END_HEADER = '\r\n\r\n'

"""
Uni HTTP constants
"""
URL_PADDING_BYTE_LEN = 0
URL_PADDING_HEX_LEN = URL_PADDING_BYTE_LEN * 2

MAX_CHAFF_RESP_RECEIVED = 5
HTTP_SEND_CHAFF_INTERVAL = 0.5
TLS_SEND_CHAFF_INTERVAL = 0.0835

HTTP_UNI_CHAFF_URL_PATH = '0' * 256
HTTP_UNI_CHAFF_COVERT_DATA_URL_PATH = '0' * 768
TLS_UNI_CHAFF_URL_PATH = '0' * 256 * 5
TLS_UNI_CHAFF_URL_PATH_LEN = len(TLS_UNI_CHAFF_URL_PATH)

HTTPU_BYTE_HASHLEN = 8
HTTPU_HEX_HASHLEN = 2 * HTTPU_BYTE_HASHLEN
HTTPU_HASHSEP = ':'

HTTPU_MAX_URL_LEN = 256

HTTPU_CURVEBALLHELLO = "WelcomeToCurveball"
HTTPU_CLIENTHELLO = "ConnectToCurveball"
TLSUNI_CURVEBALLHELLO = "WelcomeToCurveball"

HTTP_UNI_CT_DP_PORT = 57777
TLS_UNI_CT_DP_PORT = 57778

"""
Bittorent constants
"""

# It is on this port that the DR looks for bittorent traffic
#
BITTORRENT_SERVER_PORT = 6881

"""
Length in bytes of the encrypted premaster secret for RSA
"""
TLS_PMS_LENGTH = 48
TLS_PMS_ENCRYPTED_LENGTHS = (64, 128, 256, 512, 1024, 2048)
TLS_CB_SENTINEL_LABEL_BYTES = 24




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
DP Private Key
"""
DP_PRIV_KEY_NAME = "priv.pem"
RELATIVE_PATH_BUILD_PRIV_KEY = os.path.join('..', '..',
        'build', 'auth', 'certs')
RELATIVE_PATH_PRIV_KEY = os.path.join('..', 'auth', 'certs')

"""
DP Handshake and Covert Tunnel States
"""
# Bidirectional HTTP
STATE_2   = 'Init'
STATE_2_5 = 'State 2.5:  waiting for http response from DH'
STATE_4   = 'State 4:  waiting for premaster'
STATE_4_5 = 'State 4.5:  send welcome in response to premaster'
STATE_6  =  'State 6:  tunnel is ready'

# Unidirectional HTTP
STATE_2_UNI = 'Init'
STATE_4_UNI = 'State 6:  tunnel is ready'

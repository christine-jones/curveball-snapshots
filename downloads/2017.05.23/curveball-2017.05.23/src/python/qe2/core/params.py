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

"""
Parameters used across the system

This could be parameterized in a cleaner fashion, but it's
handy to have everything in one file for development/debugging.
"""

PARAMS = {
    'SERVER_NAME' : 'quilt',

    'SERVER_LISTEN_PORT' : 4000,
    'SERVER_APP_HOST' : '',
    'SERVER_APP_PORT' : 4002,

    'CLIENT_LISTEN_NAME' : 'localhost',
    'CLIENT_LISTEN_PORT' : 4001,

    # Seconds to wait for a channel in the start state.
    # After this many seconds, it is considered failed.
    #
    'MAX_CHAN_START_TIME' : 4,
}

class Qe2Params(object):
    """
    Implements the server side of the Qe2 connection protocol
    """

    def __init__(self, test_only=False):
        pass

    @staticmethod
    def get(param_name):
        return PARAMS[param_name]

    @staticmethod
    def set(param_name, param_value):
        PARAMS[param_name] = param_value

if __name__ == '__main__':

    def test_main():
        """
        """

        pass

    test_main()



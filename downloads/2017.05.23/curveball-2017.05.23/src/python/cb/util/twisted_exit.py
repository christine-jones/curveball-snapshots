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
A wrapper for twisted's reactor.run() to make it easier to return
a meaningful exit status
"""

import sys

EXIT_STATUS = 0

def run(reactor, do_exit=True):
    """
    Call the given reactor's run method, and wait for it to return or
    raise an exception, and then either call sys.exit() with the current
    EXIT_STATUS (the default) or just return the current EXIT_STATUS
    (if do_exit is False).

    If reactor.run() raises an exception, the exception is discarded and
    EXIT_STATUS is set to 1 if it is zero, or returned as-is if it has already
    been set to reflect the abnormal termination of reactor.run().
    """

    global EXIT_STATUS

    try:
        reactor.run()
    except BaseException, _exc:
        if EXIT_STATUS == 0:
            EXIT_STATUS = 1

    if do_exit:
        sys.exit(EXIT_STATUS)
    else:
        return EXIT_STATUS


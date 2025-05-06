#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2016 - Raytheon BBN Technologies Corp.
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
Set up parameters used by the cb.util.cblogging module.

This module should be imported, and its methods used to
initialize the logging parameters, BEFORE any loggers are created
or used, which in practical terms means BEFORE any other cb modules
are imported.

This is a big clunky, but it lets us parameterize some of the
cblogging behavior without rewriting a large number of legacy
modules.
"""

# Start with a default of stdout, so that any messages that are
# emitted before we set up the logger go to stdout instead of
# triggering another failure
#
LOGTYPE = 'stdout'

def set_logtype(logtype):
    """
    Set the log file for loggers created in the future.  Has no
    effect on any loggers already created!

    Note that syslog has not been well-tested yet, and may be
    considered experimental.
    """

    assert logtype in ['syslog', 'rotfile', 'stdout', 'stderr'], \
            'invalid logtype'

    cb.util.cblogging_setup.LOGTYPE = logtype


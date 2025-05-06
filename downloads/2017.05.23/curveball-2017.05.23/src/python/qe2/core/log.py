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

The Qe2 Logging Setup

Use names like: 'qe2', 'qe2.endpoint', etc
"""

import logging

class Qe2Logger(object):
    """
    Wrapper class to keep the global namespace clean
    """

    @staticmethod
    def init_logger(loggername='qe2', level=logging.WARNING):
        """
        Initialize a logger for this process.

        loggername - the name of the logger.  This should be the prefix
            that all of the other loggers are going to use.  The default
            is 'qe2'.

        level - the active logging level
        """

        # Set up a specific logger with our desired output level
        logger = logging.getLogger(loggername)
        logger.setLevel(level)

        # After we create the logger, it seems that we need need to
        # stash a reference to it somewhere so we don't lose it.
        #
        Qe2Logger.logger = logger

        formatter = logging.Formatter(
                '%(asctime)s %(name)s %(module)s:%(lineno)d ' +
                '%(levelname)s: %(message)s')

        serr = logging.StreamHandler()

        serr.setFormatter(formatter)

        Qe2Logger.logger.addHandler(serr)

Qe2Logger.init_logger()

QE2LOG = logging.getLogger('qe2')

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
Test scaffolding for a basic quilt server
"""

from twisted.internet import reactor

from qe2.core.server import Qe2ServerListener

def test_main():
    """
    Start a quilt server listening on the test port.

    TODO: use the qe2.core.params
    """

    listener = Qe2ServerListener('', 4000)
    reactor.run()

if __name__ == '__main__':
    test_main()

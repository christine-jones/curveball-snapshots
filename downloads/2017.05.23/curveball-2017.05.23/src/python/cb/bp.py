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

import sys

# find .. -exec grep -nH -e 'cb.bp.bp' \{\} +

# edit this list to have the breakpoints you want to actually hit
# then, in the debugger, put a breakpoint on cb.bp.breakpoint
# top number used so far: 18

# 10 is a call to log_error from the connection_monitor, so it should
# probably be left in the list  

breakpoint_set = [10, 17, 18 ]

def bp(which, msg):
    if which in breakpoint_set:
        print >> sys.stderr, "Hit pseudo-breakpoint: %s" % msg
        breakpoint(msg)

def breakpoint(msg):
    return

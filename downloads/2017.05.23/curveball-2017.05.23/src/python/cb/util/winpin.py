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

import sys
import subprocess

def win_pin_routes(addrs, gateway=None):
    """
    Pin a route through the interface that faces the decoy

    FIXME: this is specific to the windows demo, because we haven't
    figure out how to generalize it yet.
    """

    if gateway == None:
	current_metric = 10000
        proc = subprocess.Popen(['route', 'print', '0.0.0.0'], shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, _err) = proc.communicate()
        lines = out.split('\r\n')
        for line in lines:
	    # print "line = [%s]" % (line,)
	    splits = line.split()

	    if len(splits) != 5:
		continue
	    # print "splits = %s" % (str(splits),)
            (destnet, mask, r_gateway, iface_addr, metric) = line.split()
            if destnet == '0.0.0.0' and mask == '0.0.0.0':
		if int(metric) < current_metric:
		    gateway = r_gateway
		    current_metric = int(metric)

    if not gateway:
        print "No gateway found!"
	return False

    print "GATEWAY [%s]" % (str(gateway),)

    for addr in addrs:
	cmd = "route add %s MASK 255.255.255.255 %s METRIC 1" % (
		str(addr), str(gateway))
	try:
	    subprocess.check_call(cmd, shell=True)
	except BaseException, _exc:
	    print 'Failed to pin route for %s' % (str(addr),)
	    print str(_exc)
	    return False
	else:
	    print 'Pinned route for %s' % (str(addr),)

    return True

if __name__ == '__main__':
    win_pin_route('1.1.1.1')


#----------------------------------------------------------------------
# Copyright (c) 2010 Raytheon BBN Technologies Corp.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and/or hardware specification (the "Work") to
# deal in the Work without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Work, and to permit persons to whom the Work
# is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Work.
#
# THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
# IN THE WORK.
#----------------------------------------------------------------------
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.

import ConfigParser
import os


def read_config(path=None):
    """Read the config file into a dictionary where each section
    of the config is its own sub-dictionary
    """
    confparser = ConfigParser.RawConfigParser()

    # If a path is given, use it (and no other).  If no path
    # is given, try the decoyproxy.conf in the current directory
    #
    # NOTE: there used to be several defaults, which is why paths
    # is as a list that may contain multiple paths, but now the
    # assumption is that there is a path.
    #
    if path:
        paths = list([path])
    else:
        paths = [ './decoyproxy.conf' ]

    found_file = None
    for fname in paths:
        found_file = confparser.read(fname)
        if found_file:
            break

    if not found_file:
        print 'ERROR: config file %s could not be loaded' % str(paths)
        return None

    config = {}

    for section in confparser.sections():
        config[section] = {}
        for (key, val) in confparser.items(section):
            config[section][key] = val

    return config

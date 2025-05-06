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

import os
import py_compile
import sys

from distutils.core import setup

# Load the version name relative to the directory that this
# script lives in.
#
DIRNAME = os.path.normpath(
        os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))
VERSION_FILE = os.path.join(DIRNAME, 'VERSION')

try:
    # Take the first token is in the VERSION file
    CB_VERSION = open(VERSION_FILE).read().strip().split()[0]
    print 'Using VERSION=[%s]' % CB_VERSION
except:
    print 'ERROR: could not read version file [%s]' % VERSION_FILE
    sys.exit(1)

# The default behavior of setup is to invoke py_compile.compile()
# without any error checking.  We can monkey-patch py_compile.compile
# with a wrapper than requests it to raise an exception (doraise=True)
# if it detects any error.
#
# NOTE: THIS ONLY DETECTS COMPILE-TIME ERRORS, which are a small subset
# of the possible errors.  It will NOT detect things like broken imports.
#
# This idea was found on stackoverflow:
# http://stackoverflow.com/questions/2230843/
#
ORIGINAL_COMPILE = py_compile.compile

def doraise_py_compile(file, cfile=None, dfile=None, doraise=False):
    ORIGINAL_COMPILE(file, cfile=cfile, dfile=dfile, doraise=True)

py_compile.compile = doraise_py_compile

try:
    setup(name='Curveball Python Utils',
            version=CB_VERSION,
            description='Curveball Python Utils',
            packages=[
                'cb',
                'cb.ccp',
                'cb.cssl',
                'cb.ct',
                'cb.ct.tls',
                'cb.ct.tlsuni',
                'cb.ct.http',
                'cb.ct.httpuni',
                'cb.ct.bittorrent',
                'cb.dr2dp',
                'cb.gui',
                'cb.gui.client',
                'cb.mole',
                'cb.noc',
                'cb.sentman',
                'cb.tcphijack',
                'cb.util',
                'cb.vpn',
                # the new quilting packages:
                'qe2', 'qe2.core', 'qe2.core.test',
                # the new remora package:
                'remora',
                # packages we no longer use:
                # 'cb.quilt',
                # 'cb.trawl',
            ])
except BaseException, exc:
    print str(exc)
    sys.exit(1)

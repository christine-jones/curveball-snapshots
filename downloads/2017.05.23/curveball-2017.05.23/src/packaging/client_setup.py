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

import glob
import os
import py_compile
import sys

from cx_Freeze import setup, Executable

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

NSS_VERSION = '3.13.3'
NSS_DIR = '../nss/nss-%s/mozilla' % NSS_VERSION
NSS_BUILDTYPE = "DBG"

if sys.argv[-1] in [ 'bdist_msi' ]:
    NSS_BUILDTYPE = "OPT"

# Dependencies are automatically detected, but it might need fine tuning.
#build_exe_options = {"packages": ["os"], "excludes": ["tkinter"]}
#build_exe_options = {"packages":["atexit","PySide"]}
sys.path.append(os.path.join(DIRNAME, '..', 'python'))

include_files = []

# Include client-agent and its NSS/NSPR dlls and certdb
pattern = '%s/security/nss/cmd/dmtest/WINNT*%s.OBJ/client-agent.exe' % (
        NSS_DIR, NSS_BUILDTYPE)
client_agents = glob.glob(pattern)

if not client_agents:
    print 'NO client-agent.exe found in (%s)' % pattern
    print 'Did you build NSS (build type %s)?' % NSS_BUILDTYPE
    sys.exit(1)

client_agent = client_agents[0]

include_files.append((client_agent, 'nss-bin/client-agent.exe'))
include_files.append(('../test/auth/certs/pub.pem', 'auth/certs/pub.pem'))

for fname in ['cert8.db', 'curveball-pub.pem', 'key3.db', 'secmod.db']:
    include_files.append(
            ('../test/auth/certdb/%s' % fname, 'nss-bin/certdb/%s' % fname))

pattern = "%s/dist/WINNT*%s.OBJ/lib/*.dll" % (NSS_DIR, NSS_BUILDTYPE)
dlls = glob.glob(pattern)
for dll in dlls:
    src = dll
    dst = 'nss-bin/%s' % os.path.basename(dll)
    include_files.append((src,dst))

if not dlls:
    print 'NO DLLs FOUND in (%s)' % pattern
    print 'Did you build NSS (build type %s)?' % NSS_BUILDTYPE
    sys.exit(1)

print include_files
build_exe_options = {"packages": ["atexit", "cb", "PySide.QtXml"],
                     "include_files": include_files}

# GUI applications require a different base on Windows (the default is for a
# console application).

# If you need to see stdout you want console not GUI!
base = None
if sys.platform == "win32":
#    base = "Win32GUI"
    base = "Console"
    
try:
    setup(name="CurveballClient",
            version=CB_VERSION,
            description='Curveball Client',
            options = {"build_exe": build_exe_options},
            executables = [
                Executable("../python/cb/gui/client/client_gui.py",
                           base=base,
                           shortcutName="BBN Curveball",
                           shortcutDir="DesktopFolder",
                           icon="../python/cb/gui/client/res/app_icon.ico"),
                Executable("../scripts/curveball-client", base=base),
                Executable("../scripts/curveball-key-config", base=base)])
except BaseException, exc:
    print str(exc)
    sys.exit(1)

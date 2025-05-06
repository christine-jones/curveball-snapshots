# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017 and in
# part by a grant from the United States Department of State.
# The opinions, findings, and conclusions stated herein are those
# of the authors and do not necessarily reflect those of the United
# States Department of State.
#
# Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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

# This is a Makefile for click plus the BBN Curveball click elements,
# intended to be used for use with BBN Curveball.
#
# DOES NOT SUPPORT ALL OF THE FEATURES SUPPORTED BY STANDARD CLICK.
# DOES NOT SUPPORT LINUX KERNEL MODULES, SOME DRIVERS, AND SOME
# ELEMENTS.
#

CLICK_VERSION	= fastclick
CLICK_DIR	= click-$(CLICK_VERSION)

# fastclick built seperate from curveball; configure where to find fastclick
CBCLICK_OPTIONS	=
CBCLICK_OPTIONS	+= --with-click=/usr/local
CBCLICK_OPTIONS	+= CC=gcc-4.7 CXX=g++-4.7

SUDO		= /usr/bin/sudo
MAKEFILE	= $(lastword $(MAKEFILE_LIST))
# fastclick built separate from curveball
SRCDIR_FILE	= /usr/local/share/click/srcdir

# If we're building in our home directory (or another development area)
# then we don't need sudo to succeed.  If we're building and installing in
# /opt/curveball, however, then we need sudo or else permissions will be
# a problem.
#
ifeq ($(PWD), /opt/curveball/click)
    BUILDSUDO = $(SUDO)
else
    BUILDSUDO =
endif

# test whether there's any version of click installed, and if so
# whether it matches the version we want to build, and halts if
# there's a version and it doesn't match what we need.  Otherwise,
# builds/installs the base click, and then builds/installs the
# BBN Curveball elements.
#
# fastclick is made/installed separately from curveball;
# only build/install the BBN Curveball elements
build:
	$(MAKE) -f $(MAKEFILE) cbbuild

# Only builds/installs the BBN Curveball elements.
#
# fastclick built separate from curveball; don't install if not there
cbbuild:
	$(MAKE) -f $(MAKEFILE) test_click_version
	cd curveball && $(BUILDSUDO) ./configure $(CBCLICK_OPTIONS)
	cd curveball && $(BUILDSUDO) $(MAKE)
	cd curveball && $(SUDO) $(MAKE) install

# If there is a version installed, then we need to check whether it's
# the version we are about to install.  If not, then gripe.
#
test_click_version:
	@test ! -f $(SRCDIR_FILE) \
	|| test $$(cat $(SRCDIR_FILE) | sed -e 's/.*\///' ) \
	    = $(CLICK_VERSION) \
	|| (echo "" && \
	    echo "ERROR: CLICK VERSION MISMATCH: wrong version installed:" && \
	    cat $(SRCDIR_FILE) && \
	    echo "" && \
	    false)

clean:
	cd curveball && $(BUILDSUDO) $(MAKE) clean
	cd curveball && $(BUILDSUDO) $(SUDO) ./configure $(CBCLICK_OPTIONS)

# Not really spotless, because it doesn't uninstall.  It only cleans up the
# build area.
#
spotless:
	$(MAKE) clean


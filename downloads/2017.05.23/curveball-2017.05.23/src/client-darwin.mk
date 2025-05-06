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

# Top-level platform-specific makefile for the curveball client.
# This is the makefile for macosx, aka darwin.
#
# Provides a target for installing the necessary packages (via "port")
# but by default assumes that they are already installed and up-to-date.

MAKEFILE_NAME := $(firstword $(MAKEFILE_LIST))

# Are you building a DBG or and OPT version of NSS?
# Set these NSSTYPE and NSS_OPT_MAKE_FLAG accordingly.
#
# Note that when switching between DBG and OPT you probably want to 
# make .CLEAN_NSS 
#
NSSTYPE	= DBG
# NSSTYPE	= OPT

NSS_OPT_MAKE_FLAG=
ifeq ($(NSSTYPE), OPT)
	NSS_OPT_MAKE_FLAG=BUILD_OPT=1
endif

NSSVERSION	= 3.13.3


# From the mozilla-style Makefiles
OS_ARCH := $(subst /,_,$(shell uname -s))

# for debian names
DEB_HOSTTYPE := \
	$(shell /usr/bin/arch | sed -e 's/x86_64/amd64/' -e 's/i686/i386/')

BUILD_TREE_TOOL = ./packaging/build-tree
BUILD_TREE	:= $(shell $(BUILD_TREE_TOOL) dirname)

default:	install

# remove everything we've built.  Don't uninstall anything, however.
#
clean:		.CLEAN_NSS .CLEAN_LOGS

# Assumes that 'port' is installed.
CLIENT_PKGS	= \
	python27 py27-ipaddr py27-twisted py27-m2crypto \
	py27-pexpect py27-pip py27-socksipy-branch \
	tuntaposx

NSS_SRC_DIR	= nss/nss-$(NSSVERSION)/mozilla
DMTEST_EXE_DIR	= $(NSS_SRC_DIR)/security/nss/cmd/dmtest/$(OS_ARCH)*$(NSSTYPE).OBJ
NSS_BUILD_DIR	= $(NSS_SRC_DIR)/dist/$(OS_ARCH)*$(NSSTYPE).OBJ

IS64 := $(shell uname -m | grep -q x86_64  && echo 'USE_64=1')
.NSS:
	@echo '## Config/build the curveball NSS'
	echo $(IS64)
	cd $(NSS_SRC_DIR)/security/nss && \
		$(MAKE) nss_build_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(NSS_SRC_DIR)/security/nss && \
		$(MAKE) install $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd nss/nss-$(NSSVERSION)/mozilla/security/nss/cmd/dmtest && \
		$(MAKE) nss_build_all $(IS64) $(NSS_OPT_MAKE_FLAG) && \
		$(MAKE) install $(IS64) $(NSS_OPT_MAKE_FLAG)

# This is a hack, and should eventually be fixed.
# FIXME
# client-agent is built without an install home, so in order to
# get the dylibs to load properly we need to put them into bin/
# (instead of in lib/).
# Yuck.
#
.NSS_INSTALL: .NSS
	$(BUILD_TREE_TOOL) create test
	cp -p $(DMTEST_EXE_DIR)/client-agent $(BUILD_TREE)/bin/
	cp -p $(NSS_BUILD_DIR)/lib/*dylib $(BUILD_TREE)/bin
	cp -pRL test/auth $(BUILD_TREE)/

.CLEAN_NSS:
	@echo '## Cleaning the curveball NSS'
	cd $(NSS_SRC_DIR)/security/nss && \
		$(MAKE) nss_clean_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(NSS_SRC_DIR)/security/nss/cmd/dmtest && \
		$(MAKE) clean $(IS64) $(NSS_OPT_MAKE_FLAG)

.COPY_NODE_CERTS:
	/bin/rm -rf $(BUILD_TREE)/auth/nodes
	mkdir -p $(BUILD_TREE)/auth/nodes/
	cp -L CA/CERTS/*.key $(BUILD_TREE)/auth/nodes/
	chmod 400 $(BUILD_TREE)/auth/nodes/*.key
	cp -L CA/CERTS/*.pem $(BUILD_TREE)/auth/nodes/
	chmod 444 $(BUILD_TREE)/auth/nodes/*.pem
	/bin/rm -rf $(BUILD_TREE)/auth/CA/
	mkdir -p $(BUILD_TREE)/auth/CA/
	cp -L CA/CA/*.pem $(BUILD_TREE)/auth/CA/
	chmod 444 $(BUILD_TREE)/auth/CA/*.pem

.CLEAN_LOGS:
	@echo '## Cleaning logs'
	(cd scripts; rm -f *.log *.log.1)

install_tree:
	$(BUILD_TREE_TOOL) create test

# Only install a subset of the entire set of modules and scripts
# (but still probably more than strictly necessary for only a client)
#
CLIENT_SCRIPTS = \
	scripts/curveball-client \
	scripts/curveball-darwin \
	scripts/curveball-key-config \
	scripts/curveball-tweet \
	scripts/curveball-my-conns \
	scripts/curveball-pin-route

install_scripts:
	cd python ; ../packaging/python_setup.py install \
		--home=$(BUILD_TREE)/python \
		--install-purelib=$(BUILD_TREE)/python \
		--install-data=$(BUILD_TREE)/python
	-tar cf - $(CLIENT_SCRIPTS) | ( cd $(BUILD_TREE) ; tar -xf - )
	-tar cf - sentinels | ( cd $(BUILD_TREE) ; tar -xf - )

install_pkgs:
	sudo port install $(CLIENT_PKGS)
	sudo pip-2.7 install twython

install:	install_tree install_pkgs .NSS_INSTALL .COPY_NODE_CERTS
	$(BUILD_TREE_TOOL) create test
	$(MAKE) -f $(MAKEFILE_NAME) install_scripts

remove_build:
	$(BUILD_TREE_TOOL) spotless

tarball:	remove_build install
	cd $(BUILD_TREE)/.. ; tar zcf cb-$(DEB_HOSTTYPE).tar.gz build


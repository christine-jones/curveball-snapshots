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

# Top-level platform-specific makefile for the curveball client.
# This is the makefile for the Ubuntu 14.04 client.
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

.NSS_INSTALL: .NSS
	$(BUILD_TREE_TOOL) create test
	cp -p $(DMTEST_EXE_DIR)/client-agent $(BUILD_TREE)/bin/
	cp -p $(NSS_BUILD_DIR)/lib/* $(BUILD_TREE)/lib/
	cp -pRL test/auth $(BUILD_TREE)/

.CLEAN_NSS:
	@echo '## Cleaning the curveball NSS'
	cd $(NSS_SRC_DIR)/security/nss && \
		$(MAKE) nss_clean_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(NSS_SRC_DIR)/security/nss/cmd/dmtest && \
		$(MAKE) clean $(IS64) $(NSS_OPT_MAKE_FLAG)

.COPY_CERTS:
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
	scripts/curveball-key-config \
	scripts/curveball-my-conns \
	scripts/curveball-pin-route \
	scripts/cb-socks-only \
	scripts/curveball-grab \
	scripts/curveball-tweet

install_scripts:
	cd python ; ../packaging/python_setup.py install \
		--home=$(BUILD_TREE)/python \
		--install-purelib=$(BUILD_TREE)/python \
		--install-data=$(BUILD_TREE)/python
	-tar cf - $(CLIENT_SCRIPTS) | ( cd $(BUILD_TREE) ; tar -xf - )

# Check that this is run on Ubuntu 1604.  Things could get weird
# if we ran this elsewhere.
#
is_ubuntu1604:
	test $$(lsb_release -is) = "Ubuntu" \
	    || (echo "Error: wrong operating system" && false)
	test $$(lsb_release -rs) = "16.04" \
	    || (echo "Error: wrong operating system version" && false)

# See https://curveball.ir.bbn.com/projects/curveball/wiki/BuildOnUbuntuTen
# for additional prerequisites.
install_pkgs: is_ubuntu1604
	sudo apt-get -y install python2.7-dev curl swig
	sudo apt-get -y install python-setuptools
	sudo apt-get -y install python-m2crypto
	sudo apt-get -y install python-ipaddr
	sudo apt-get -y install python-twisted
	sudo apt-get -y install zlib1g-dev
	sudo apt-get -y install python-socks python-pexpect python-twython

install:	install_tree install_pkgs .NSS_INSTALL .COPY_CERTS
	$(BUILD_TREE_TOOL) create test
	$(MAKE) -f $(MAKEFILE_NAME) install_scripts

remove_build:
	$(BUILD_TREE_TOOL) spotless

tarball:	remove_build install
	cd $(BUILD_TREE)/.. ; tar zcf cb-$(DEB_HOSTTYPE).tar.gz build

debfile:	remove_build install
	./packaging/make-deb-client

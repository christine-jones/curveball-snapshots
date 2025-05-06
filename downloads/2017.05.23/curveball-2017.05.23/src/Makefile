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

# Top-level makefile for the curveball sources
#
# Specific to Linux (Ubuntu 12.04) and builds both the Curveball client
# and the Curveball servers.
#
# Installs packages that need to be installed in order to build and run,
# builds things that need to be built

# Are you building a DBG or and OPT version of NSS?
# Set these two vbls accordingly
# Note that when switching between DBG and OPT you probably want to 
# make .CLEAN_NSS 

NSSTYPE=DBG
# NSSTYPE=OPT

NSS_OPT_MAKE_FLAG=
ifeq ($(NSSTYPE), OPT)
		NSS_OPT_MAKE_FLAG=BUILD_OPT=1
endif

# From the mozilla-style Makefiles
OS_ARCH := $(subst /,_,$(shell uname -s))

BUILD_TREE_TOOL = ./packaging/build-tree
BUILD_TREE	:= $(shell $(BUILD_TREE_TOOL) dirname)

NSSVERSION	= 3.13.3
NSS_BASE_DIR	= nss/nss-$(NSSVERSION)/mozilla
NSS_SRC_DIR	= $(NSS_BASE_DIR)/security/nss
NSS_BUILD_DIR	= $(NSS_BASE_DIR)/dist/$(OS_ARCH)*$(NSSTYPE).OBJ
DMTEST_SRC_DIR	= $(NSS_SRC_DIR)/cmd/dmtest
DMTEST_EXE_DIR	= $(DMTEST_SRC_DIR)/$(OS_ARCH)*$(NSSTYPE).OBJ

.PHONY:	install clean is_ubuntu1204 \
	.BASE_PACKAGES .CLIENT_PACKAGES \
	.NSS .NSS_INSTALL .NSS_CLEAN \
	.COPY_NODE_CERTS \
	.CLICK .CLEAN_CLICK .CLEAN_LOGS .DPS \
	install_tree install_click install_scripts \
	uninstall remove_build debfile

# default: build and install everything in the test area (../build)
default:	install

# remove everything we've built.  Don't uninstall anything, however.
#
clean:		.CLEAN_NSS .CLEAN_CLICK .CLEAN_LOGS
	rm -rf python/build
	rm -rf tmp-debbuild
	sudo rm -rf ../build

# PACKAGES: things curveball needs to run and/or test.
#
# g++ is needed to build click for the dr (only
# the libraries are needed to run the dr).
# texinfo is needed to build the info pages for click.
# dante-server is needed for the dp.
# openssh-server is convenient but not (always) necessary
# quagga is needed by core (but maybe needed if we're not running core?)
#
# bridge-utils, ebtables, libev3, libtk-img, tck: used by CORE.
# # python-pyside pyside-tools 

BASE_PKGS	= \
	g++ texinfo dante-server openssh-server quagga \
	python-dev iperf python-dumbnet swig libnspr4-dev \
	python-dpkt python-ipaddr python-m2crypto libsqlite3-dev \
	bridge-utils ebtables libev-dev libtk-img tcl tk tsocks proxychains \
	libnetfilter-queue1 nmap python-pyside pyside-tools \
	python-pip xvfb xserver-xephyr tightvncserver zlib1g-dev \
	python-bitarray python-pexpect fakeroot lintian \
	python-tlslite \
	ethtool libpcap0.8-dev \
	python-socksipy python-pcapy python-netifaces python-dnspython

CLIENT_PKGS	= \
	python-pip xvfb xserver-xephyr tightvncserver zlib1g-dev 

# Check that this is run on Ubuntu 1204.  Things could get weird
# if this Makefile is used elsewhere.
#
is_ubuntu1204:
	@test $$(lsb_release -is) = "Ubuntu" \
	    || (echo "Error: wrong operating system" && false)
	@test $$(lsb_release -rs) = "12.04" \
	    || (echo "Error: wrong operating system version" && false)

.BASE_PACKAGES:	is_ubuntu1204
	@echo '## Fetching and installing packages'
	sudo apt-get update
	sudo apt-get -y install $(BASE_PKGS)
	sudo apt-get -y -f install

.CLIENT_PACKAGES: is_ubuntu1204 .BASE_PACKAGES
	sudo apt-get -y install $(CLIENT_PKGS)
	sudo apt-get -y -f install
	sudo pip install pyvirtualdisplay
	sudo pip install twython
	# sudo pip install -U selenium

IS64 := $(shell uname -m | grep -q x86_64  && echo 'USE_64=1')

.NSS:
	cd $(NSS_SRC_DIR) && \
	    NSS_ENABLE_ECC=1 $(MAKE) nss_build_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(NSS_SRC_DIR) && \
	    NSS_ENABLE_ECC=1 $(MAKE) install $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(DMTEST_SRC_DIR) && \
	    NSS_ENABLE_ECC=1 $(MAKE) nss_build_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(DMTEST_SRC_DIR) && \
	    NSS_ENABLE_ECC=1 $(MAKE) install $(IS64) $(NSS_OPT_MAKE_FLAG)

.NSS_INSTALL: .NSS
	$(BUILD_TREE_TOOL) create test
	cp -p $(DMTEST_EXE_DIR)/client-agent $(BUILD_TREE)/bin/
	cp -pRL $(NSS_BUILD_DIR)/lib/ $(BUILD_TREE)/
	cp -pRL test/auth $(BUILD_TREE)/

.CLEAN_NSS:
	@echo '## Cleaning the curveball NSS'
	cd $(NSS_SRC_DIR) && \
	    $(MAKE) nss_clean_all $(IS64) $(NSS_OPT_MAKE_FLAG)
	cd $(DMTEST_SRC_DIR) && \
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

.CLICK:	.BASE_PACKAGES
	cd click && $(MAKE) build

.CLEAN_CLICK:
	cd click && $(MAKE) clean

.CLEAN_LOGS:
	@echo '## Cleaning logs'
	(cd scripts; rm -f *.log *.log.?)

# Not generally necessary; the DP will do this for itself.
# (It doesn't help to do this on the build machine unless the
# build machine is the DP.)
#
.DPS:
	@echo 'making sure dante will run on your system'
	./packaging/dante-links
	@echo 'Configuring the decoy proxy'
	cd scripts && sudo python ./cb-dp -s

install_tree:
	$(BUILD_TREE_TOOL) create test

install_click:	.CLICK
	$(BUILD_TREE_TOOL) create test
	-mkdir -p $(BUILD_TREE)/click/curveball
	cp click/curveball/fastclick-router.click $(BUILD_TREE)/click/curveball/
	cp click/curveball/fastclick-multi-dp.click $(BUILD_TREE)/click/curveball/

install_scripts:
	cd python ; ../packaging/python_setup.py install \
		--home=$(BUILD_TREE)/python \
		--install-purelib=$(BUILD_TREE)/python \
		--install-data=$(BUILD_TREE)/python
	-tar cf - scripts | ( cd $(BUILD_TREE) ; tar -xf - --overwrite)
	-tar cf - experiments | ( cd $(BUILD_TREE) ; tar -xf - --overwrite)
	-tar cf - test | ( cd $(BUILD_TREE) ; tar -xf - --overwrite)

install:	install_tree install_click .NSS_INSTALL .COPY_NODE_CERTS
	cp LICENSE NOTICE ../build
	$(BUILD_TREE_TOOL) create test
	cd python/cb/gui/client ; $(MAKE)
	$(MAKE) install_scripts

uninstall:
	$(BUILD_TREE_TOOL) spotless

remove_build:
	$(BUILD_TREE_TOOL) spotless
	rm -f curveball_*.deb

debfile:	remove_build install
	./packaging/make-deb

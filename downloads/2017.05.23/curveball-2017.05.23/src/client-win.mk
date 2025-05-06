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

# Top-level windows-specific makefile for the curveball client.
# This makefile is intended for win7, and should build a
# MSI file that will work on win7 or win8.
#
# NOTE: must be run within a mozilla-build/start-mscv9 shell.

# Builds both the DBG and OPT versions of NSS,
# because we use DBG for development but must use OPT
# for redistribution.

NSSVERSION	= 3.13.3

MOZ_SRC_DIR	= ./nss/nss-$(NSSVERSION)/mozilla
NSS_SRC_DIR	= $(MOZ_SRC_DIR)/security/nss
DMTEST_DIR	= $(MOZ_SRC_DIR)/security/nss/cmd/dmtest

# We need to add the directories for pyside-rcc and pyside-uic
# to our PATH because otherwise the Mozilla build won't pick
# them up from our Windows %PATH%.
#
# If you install a different PySide build, then you MUST change
# PYSIDEPKG (at the very least)
#
# NOTE: we must spell out the path to the Python we want, because
# the Mozilla build environment installs a second copy of Python
# and it's not compatible with the one we want.
#
PYTHONDIR	= /c/Python27
PYTHONEXE	= $(PYTHONDIR)/python
PYSIDEPKG	= PySide-1.2.1-py2.7-win32.egg
PYSIDEDIR	= $(PYTHONDIR)/lib/site-packages/$(PYSIDEPKG)/PySide
PATH		:= $(PYSIDEDIR):$(PYTHONDIR)/scripts:$(PATH)

# We don't use IS64 today, because we always build 32-bit on win32,
# but I'm keeping it here for the future.
#
# If we ever change this, then we need to change client_setup.py,
# which assumes it knows the name of the architecture.
#
IS64 := $(shell uname -m | grep -q x86_64  && echo 'USE_64=1')
IS64 =

default:	build-dev

# remove everything we've built, including the build and MSI files.
# Don't uninstall anything, however.
#
clean:		.CLEAN_NSS
	rm -rf packaging/build packaging/dist

.CLIENTGUI:
	cd python/cb/gui/client; $(MAKE)

.NSS-DBG:
	@echo '## Config/build DBG version of the curveball NSS'
	cd $(NSS_SRC_DIR) ; $(MAKE) nss_build_all $(IS64)
	cd $(DMTEST_DIR)  ; $(MAKE) nss_build_all $(IS64)

.NSS-OPT:
	@echo '## Config/build OPT version of the curveball NSS'
	cd $(NSS_SRC_DIR) ; $(MAKE) nss_build_all $(IS64) BUILD_OPT=1
	cd $(DMTEST_DIR)  ; $(MAKE) nss_build_all $(IS64) BUILD_OPT=1

.CLEAN_NSS:
	@echo '## Cleaning the curveball NSS'
	cd $(NSS_SRC_DIR) ; $(MAKE) clean $(IS64)
	cd $(DMTEST_DIR)  ; $(MAKE) clean $(IS64)
	cd $(NSS_SRC_DIR) ; $(MAKE) clean $(IS64) BUILD_OPT=1 
	cd $(DMTEST_DIR)  ; $(MAKE) clean $(IS64) BUILD_OPT=1 

build-dev: .NSS-DBG .CLIENTGUI
	cd packaging ; $(PYTHONEXE) client_setup.py build

build-msi: .NSS-OPT .CLIENTGUI
	rm -rf packaging/build
	cd packaging ; $(PYTHONEXE) client_setup.py bdist_msi
	mv packaging/dist/CurveballClient-*-win32.msi .


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
# This is the makefile for android.
#
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
OS_ARCH = Android

BUILD_TREE_TOOL = ./packaging/build-tree -r build.android
BUILD_TREE	:= $(shell $(BUILD_TREE_TOOL) dirname)
ANDROID_HELPER	= ./packaging/android-helper

NSSVERSION	= 3.13.3
NSS_BASE_DIR	= nss/nss-$(NSSVERSION)/mozilla
NSS_SRC_DIR	= $(NSS_BASE_DIR)/security/nss
NSS_BUILD_DIR	= $(NSS_BASE_DIR)/dist/$(OS_ARCH)*$(NSSTYPE).OBJ
DMTEST_SRC_DIR	= $(NSS_SRC_DIR)/cmd/dmtest
DMTEST_EXE_DIR	= $(DMTEST_SRC_DIR)/$(OS_ARCH)*$(NSSTYPE).OBJ

ANDROID_NDK = $(shell $(ANDROID_HELPER) android-ndk)

# default: build and install everything
default:	build

# remove everything we've built.  Don't uninstall anything, however.
#
clean:		.CLEAN_NSS
	rm -rf python/build
	rm -rf ../build.android
	rm -rf android/Curveball-for-Android/bin
	rm -rf android/Curveball-for-Android/gen
	rm -rf android/Curveball-for-Android/res/raw/python
	rm -f android/Curveball-for-Android/build.xml
	rm -f android/Curveball-for-Android/local.properties
	rm -f android/Curveball-for-Android/proguard-project.txt
	rm -f android/Curveball-for-Android/project.properties
	rm -f android/Curveball-for-Android/res/raw/curveball.zip

.CLEAN_NSS:
	$(PATCH_NSS_ANDROID)
	@echo '## Cleaning the curveball NSS'
	export ANDROID_NDK=$(ANDROID_NDK) OS_TARGET=Android CROSS_COMPILE=1; \
	    cd $(NSS_SRC_DIR) && $(MAKE) nss_clean_all $(NSS_OPT_MAKE_FLAG)
	@echo '## Cleaning dmtest'
	export ANDROID_NDK=$(ANDROID_NDK) OS_TARGET=Android CROSS_COMPILE=1; \
	    cd $(DMTEST_SRC_DIR) && $(MAKE) clean $(NSS_OPT_MAKE_FLAG)
	$(REVERSE_PATCH_NSS_ANDROID)

# Android specific rules
#

ROOTDIR := $(shell echo $$(pwd))
PATCH_NSS_ANDROID = patch -d $(ROOTDIR)/$(NSS_BASE_DIR) -p3 \
		    < $(ROOTDIR)/android/nss_android.patch
REVERSE_PATCH_NSS_ANDROID = patch -d $(ROOTDIR)/$(NSS_BASE_DIR) \
		    -f -r -s -R --no-backup-if-mismatch -p3 \
		    < $(ROOTDIR)/android/nss_android.patch

.NSS_ANDROID:
	$(ANDROID_HELPER) check-ndk
	@echo '## Config/build the curveball NSS for Android'
	$(PATCH_NSS_ANDROID)
	export ANDROID_NDK=$(ANDROID_NDK) OS_TARGET=Android CROSS_COMPILE=1; \
	    cd $(NSS_SRC_DIR) && \
	    NSS_ENABLE_ECC=1 $(MAKE) nss_build_all $(NSS_OPT_MAKE_FLAG) && \
	    cd cmd/dmtest && \
	    NSS_ENABLE_ECC=1 $(MAKE) nss_build_all $(NSS_OPT_MAKE_FLAG) \
		|| $(REVERSE_PATCH_NSS_ANDROID)
	$(REVERSE_PATCH_NSS_ANDROID) || false

.NSS_INSTALL_ANDROID: .NSS_ANDROID install_auth
	@echo '## Install NSS on the Android'
	$(BUILD_TREE_TOOL) create test
	cp -p $(DMTEST_EXE_DIR)/client-agent $(BUILD_TREE)/bin/
	cp -pRL $(NSS_BUILD_DIR)/lib/ $(BUILD_TREE)/

install_tree:
	$(BUILD_TREE_TOOL) create test

install_auth:
	rm -rf $(BUILD_TREE)/auth
	mkdir -p $(BUILD_TREE)/auth/certs
	mkdir -p $(BUILD_TREE)/auth/certdb
	cp -p test/auth/certs/pub.pem $(BUILD_TREE)/auth/certs/
	cp -p test/auth/certdb/cert8.db $(BUILD_TREE)/auth/certdb/
	cp -p test/auth/certdb/key3.db $(BUILD_TREE)/auth/certdb/
	cp -p test/auth/certdb/secmod.db $(BUILD_TREE)/auth/certdb/
	cp -p test/auth/certdb/curveball-pub.pem $(BUILD_TREE)/auth/certdb/
	# android stuff
	mkdir -p $(BUILD_TREE)/auth/keys
	cp -p test/auth/keys/master.km $(BUILD_TREE)/auth/keys/
	cp -p test/auth/keys/master.km.orig $(BUILD_TREE)/auth/keys/

CLIENT_SCRIPTS = \
	 scripts/curveball-client \
	 scripts/curveball-key-config \
	 scripts/curveball-my-conns \
	 scripts/curveball-pin-route \
	 scripts/curveball-android-client	# android-specific

install_scripts:
	cd python ; ../packaging/python_setup.py install \
		--home=$(BUILD_TREE)/python \
		--install-purelib=$(BUILD_TREE)/python \
		--install-data=$(BUILD_TREE)/python
	-tar cf - $(CLIENT_SCRIPTS) | \
		( cd $(BUILD_TREE) ; tar -xf - --overwrite)

uninstall:
	@echo "ERROR: cannot uninstall from device via Makefile"
	@false

ANDROID_ATTACHED	:= $(shell adb devices | grep -q -w device && echo 'true')

build:	install_tree .NSS_INSTALL_ANDROID install_scripts install_auth
	cd $(BUILD_TREE) && \
		zip -r curveball.zip * && \
		cp curveball.zip ../src/android/Curveball-for-Android/res/raw/
	cd $(BUILD_TREE)/../src/android/Curveball-for-Android && \
		android update project -p . --target android-10 --name Curveball-for-Android && \
		ant debug

install:	build
	$(ANDROID_HELPER) install

remove_build:	clean


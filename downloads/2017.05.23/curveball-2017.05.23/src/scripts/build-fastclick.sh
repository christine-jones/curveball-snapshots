#!/usr/bin/env bash
#
# This material is funded in part by a grant from the United States
# Department of State. The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of the United States Department of State.
#
# Copyright 2016 - Raytheon BBN Technologies Corp.

# Netmap and FastClick must be installed before the Curveball click modules can
# be built and used

# These instructions are for building/installing netmap and fastclick on Ubuntu
# 12.04 with the Trusty LTS kernel (3.13.0).  On our test machine we use kernel
# 3.13.0-88-generic, so this string appears in some some of the commands;
# replace # it with the name of whatever kernel you are using.
#

# DEVICES is a comma-separated string of the names of the devices for which
# you wish to build install netmap drivers.
#
# Note that you cannot install a netmap driver for a device that isn't
# configured on your system (although you can *build* a driver even
# if the device isn't installed)
#
DEVICES="e1000,ixgbe"

# BASEDIR is a scratch directory where we can download and build
# the netmap and fastclick software.  If it exists, it is removed
# and recreated.
#
BASEDIR=/opt/fastclick

if [ -e "${BASEDIR}" ]; then
    sudo rm -rf "${BASEDIR}"
fi

if [ ! -d "${BASEDIR}" ]; then
    sudo mkdir -p "${BASEDIR}"
fi

if [ ! -d "${BASEDIR}" ]; then
    echo "Failed to create $BASEDIR"
    exit 1
fi

# chown to the caller, so we don't need to
# sudo every command
#
sudo chown $USER "${BASEDIR}"

# For some confusing reason, the package name for the source
# we want is lts-trusty-3.13.0 instead of linux-$(uname -r), and
# when we try to install the kernel sources it installs them
# under this name, but we can't install that name directly.
# So we have to hardcode that these two names correspond to
# each other.  Yuck.
#
KERNELVER=$(uname -r)
SOURCEVER=linux-lts-trusty-3.13.0

# look for local copies of the source, when possible
#
FASTCLICK_SRC=/opt/curveball/dependencies/fastclick-20161117.tgz
FASTCLICK_REPO="git@gitlab.decoyrouting.com:cej/fastclick.git"
NETMAP_SRC=/opt/curveball/dependencies/netmap-20160726.tgz
NETMAP_REPO="git://github.com/luigirizzo/netmap"

# 1. Download the sources and other prerequisites:

# We do this first in order to increase the probability that
# if the user needs to be prompted to unlock their ssh key,
# it will happen right away rather than after the user has
# left to get a cup of coffee.
#
# Before this will work, you need to have your ssh configured
# with a key for gitlab.decoyrouting.com (and access to the
# fastclick project).

# make sure we have git before we try to clone anything...
#
sudo apt-get install -yf git

# get the sources for netmap and our fork of fastclick:
#
if [ -f "${FASTCLICK_SRC}" ]; then
    echo "Using cached copy of FastClick"
    cd "${BASEDIR}" && tar zxf "${FASTCLICK_SRC}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to untar fastclick source"
	exit 1
    fi
else
    echo "Downloading copy of FastClick"
    cd "${BASEDIR}" && git clone "${FASTCLICK_REPO}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to clone fastclick"
	exit 1
    fi
fi

if [ -f "${NETMAP_SRC}" ]; then
    echo "Using cached copy of NetMap"
    cd "${BASEDIR}" && tar zxf "${NETMAP_SRC}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to untar netmap source"
	exit 1
    fi
else
    echo "Downloading copy of NetMap"
    cd "${BASEDIR}" && git clone "${NETMAP_REPO}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to clone netmap"
	exit 1
    fi
fi

# 2. Install prereqs:

# We need to add a non-standard repository in order to get
# the gcc-4.7 and g++-4.7 compilers for Ubuntu 12.04 LTS.
# If we don't even know about gcc-4.7, then add the test repo
# and do an update.  We don't want to blindly do this without
# checking whether the repo is already present, because the
# operation of adding a repo is not idempotent and you can
# quickly clutter up your apt-get database.

# Note that adding this repo makes many other updates available
# (if you do an upgrade later).
#
# Once we believe we have the right repos available, we install
# whatever packages we need that aren't already installed.
#
# We need like gcc-4.7 and g++-4.7 for fastclick.
# We need dpkg-dev in order for "apt-get source" to work.
# We don't always need gitk, but it's often nice to have
# around.
#
# TODO: check for any failures

dpkg -l gcc-4.7 > /dev/null
if [ $? -ne 0 ]; then
    echo "Adding test repository"
    sudo apt-get install software-properties-common python-software-properties
    sudo add-apt-repository ppa:ubuntu-toolchain-r/test
    sudo apt-get update
fi

for pkg in gccgo-4.7 g++-4.7 dpkg-dev gitk; do
    status=$(dpkg -l "$pkg" | grep "$pkg" | awk '{print $1}')
    if [ "$status" != "ii" ]; then
	echo "INSTALLING $pkg"
	sudo apt-get install -y "$pkg"
    fi
done

# get the kernel sources and install them below $BASEDIR:
#
# When we're on MERIT (if the hostname is rnd-bbn-router1)
# then we can't use apt-get source, because MERIT uses
# Canonical mirrors that aren't set up quite right.  So we
# use a tarball of the sources that I keep in my home directory
# instead.  This is lame, and fragile, but it's a quick
# workaround.
#
if [ $(hostname) = "rnd-bbn-router1" ]; then
    LTSTARBALL=/home/dellard/lts.tgz

    if [ ! -f "${LTSTARBALL}" ]; then
	echo "ERROR: cannot find LTS sources ($LTSTARBALL)"
	exit 1
    fi
    cd "${BASEDIR}" && sudo tar zxf "${LTSTARBALL}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to fetch untar linux sources"
	exit 1
    fi
else
    echo "Downloading linux-image-${KERNELVER}"
    cd "${BASEDIR}" && apt-get -q source "linux-image-${KERNELVER}"
    if [ $? -ne 0 ]; then
	echo "ERROR: failed to fetch linux sources"
	exit 1
    fi
fi


# 3. Build and install Netmap for the e1000 device:

cd "${BASEDIR}"/netmap/LINUX && \
	./configure --kernel-sources="${BASEDIR}/${SOURCEVER}" \
		--drivers="${DEVICES}" && 
	make
if [ $? -ne 0 ]; then
    echo "ERROR: failed to configure/make netmap"
    exit 1
fi

# if all goes well, then we can install:
#
cd "${BASEDIR}"/netmap/LINUX && \
	sudo make install
if [ $? -ne 0 ]; then
    echo "ERROR: failed to install netmap"
    exit 1
fi

# 4. Build and install FastClick:

cd "${BASEDIR}"/fastclick && \
	./configure --with-netmap="${BASEDIR}"/netmap/sys \
		--enable-netmap-pool \
		--enable-multithread \
		--disable-linuxmodule \
		--enable-intel-cpu \
		--enable-user-multithread \
		--verbose \
		--enable-select=poll \
		--enable-poll \
		--enable-bound-port-transfer \
		--enable-local \
		--enable-zerocopy \
		--enable-batch \
		CC=gcc-4.7 CXX=g++-4.7 \
		CFLAGS="-g -O3" CXXFLAGS="-g -std=gnu++11 -O3" && \
	make
if [ $? -ne 0 ]; then
    echo "ERROR: failed to configure/make fastclick"
    exit 1
fi

cd "${BASEDIR}"/fastclick && \
	sudo make install
if [ $? -ne 0 ]; then
    echo "ERROR: failed to install fastclick"
    exit 1
fi

exit 0

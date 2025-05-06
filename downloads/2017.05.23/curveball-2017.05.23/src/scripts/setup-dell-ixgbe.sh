#!/usr/bin/env bash
#
# This material is funded in part by a grant from the United States
# Department of State. The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of the United States Department of State.
#
# Copyright 2016 - Raytheon BBN Technologies Corp.

# Load the kernel modules and set up the interfaces
# prior to starting the Curveball/Rebound DR.
#
# THESE COMMANDS ARE SPECIFIC TO THE DELL R420 MACHINES
# WITH A PAIR OF ixgbe INTERFACES INSTALLED AS eth4 AND eth5.
# If you run this on another system, you will probably knock
# yourself off the network (at best) or leave yourself with
# a system that behaves mysteriously (at worst).

# IN_IFACE is client-facing, OUT_IFACE is decoy-facing

# TODO: figure out some way of determining whether we're
# plausibly on the correct hardware platform.  Maybe ethtool
# will tell us what the hardware looks like?

IN_IFACE=eth4
OUT_IFACE=eth5

UNSET_IPS=/opt/curveball/scripts/unset-ips

NETMAP_MODULE=/opt/fastclick/netmap/LINUX/netmap.ko
IXGBE_MODULE=/opt/fastclick/netmap/LINUX/ixgbe/ixgbe.ko

sudo rmmod ixgbe
sudo rmmod netmap

sudo insmod "${NETMAP_MODULE}"
if [ $? -ne 0 ]; then
    echo "Error: could not install module ${NETMAP_MODULE}"
    exit 1
fi

sudo insmod "${IXGBE_MODULE}"
if [ $? -ne 0 ]; then
    echo "Error: could not install module ${IXGBE_MODULE}"
    exit 1
fi

sudo ifconfig "${IN_IFACE}" up
if [ $? -ne 0 ]; then
    echo "Error: could not bring up ${IN_IFACE}"
    exit 1
fi

sudo ifconfig "${OUT_IFACE}" up
if [ $? -ne 0 ]; then
    echo "Error: could not bring up ${OUT_IFACE}"
    exit 1
fi

if [ ! -x "${UNSET_IPS}" ]; then
    echo "Error: cannot find ${UNSET_IPS}.  Is curveball installed\?"
    exit 1
fi

if [ ! -f "${NETMAP_MODULE}" ]; then
    echo "Error: netmap module not installed at $NETMAP_MODULE"
    exit 1
fi

if [ ! -f "${IXGBE_MODULE}" ]; then
    echo "Error: ixgbe module not installed at $NETMAP_MODULE"
    exit 1
fi

# It's OK if netmap isn't already installed.

sudo rmmod ixgbe
sudo rmmod netmap

sudo insmod "${NETMAP_MODULE}"
if [ $? -ne 0 ]; then
    echo "Error: could not install module ${NETMAP_MODULE}"
    exit 1
fi

sudo insmod "${IXGBE_MODULE}"
if [ $? -ne 0 ]; then
    echo "Error: could not install module ${IXGBE_MODULE}"
    exit 1
fi

# turn multiqueue off on both incoming and outgoing netmap interfaces
#
# turn off large receive offload (lro) tso, gso, and gro off on both
# incoming and outgoing netmap interfaces
#
for iface in "${IN_IFACE}" "${OUT_IFACE}"; do
    sudo ethtool -L "${iface}" combined 1
    if [ $? -ne 0 ]; then
	echo "Warning: could not disable multiqueue on $iface"
    fi

    for option in lro tso gso gro rxvlan txvlan; do
	sudo ethtool -K "${iface}" $option off
	if [ $? -ne 0 ]; then
	    echo "Warning: could not disable $option on $iface"
	fi
    done
done

sudo "${UNSET_IPS}" "${IN_IFACE}" "${OUT_IFACE}"
if [ $? -ne 0 ]; then
    echo "Error: ${UNSET_IPS} FAILED, aborting"
    exit 1
fi

sudo ifconfig "${IN_IFACE}" up
if [ $? -ne 0 ]; then
    echo "Error: could not bring up ${IN_IFACE}"
    exit 1
fi

sudo ifconfig "${OUT_IFACE}" up
if [ $? -ne 0 ]; then
    echo "Error: could not bring up ${OUT_IFACE}"
    exit 1
fi

exit 0

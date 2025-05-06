Changes since earlier versions - version 2017.05.23 

This document lists the major differences between the release of
Curveball on May 23, 2017 and earlier versions.

Note that some of these changes are experimental and might be reverted
in later versions.  The primary goal of these changes is to increase the
performance of Curveball (particularly using the Rebound protocol) by at
least an order of magnitude.

1. BRIDGE MODE

    In this version, the decoy router (DR) does NOT function as a
    router, but instead as a transparent bridge.  This means that
    topologies that worked for earlier versions of Curveball WILL NOT
    work with this version.  The DR does not route between subnets, but
    instead is just a "bump in the wire".

    See scripts/bridge-util for setting up the DR node as a bridge
    without running Curveball.

2. FASTCLICK

    The DR has been reimplemented in fastclick, instead of click, in
    order to increase performance.  We also use netmap, which is
    supported by fastclick, and is a lower-level library that gives good
    packet-handling performance for userspace applications.

    A side effect of this change is that the performance improvements
    are only available on hardware platforms that use supported
    chipsets.  Our testbed uses the ixgbe driver (for Intel NICs).

    NOTE: before starting the DR, you MUST load the correct drivers.
    See scripts/setup-dell-ixgbe.sh for an example script to configure
    the devices correctly and load the drivers.  This is meant as an
    example ONLY and is specific to the hardware configuration of our
    testbed.  You will probably need to change it for your own system.

3. SUPPORT FOR MULTIPLE DECOY PROXIES

    One of the performance bottlenecks of earlier versions of Curveball,
    particularly when using the Rebound protocol, was the overhead of
    the decoy proxy (DP).  In the original implementation, there was one
    DP per DR (and vice versa), and the DP implementation only uses a
    single hardware core.  In order to allow a single DR to handle more
    users, the DR now can distribute its load over multiple DPs.

    Each DP needs its own config file, which sets the port numbers and
    other parameters that must differ for each DP instance.  There are
    several examples in scripts/decoyproxy[0-3].conf.  Note that running
    multiple DPs requires using a config file set up correctly, because
    the default values for the parameters only work for one DP instance.

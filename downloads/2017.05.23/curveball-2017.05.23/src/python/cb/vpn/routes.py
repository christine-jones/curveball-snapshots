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

"""
Base classes for routing utils.

Right now we only support ubuntu/linux, but other platforms might have
different interfaces for controlling routes.

THESE CLASSES ARE NOT USED BY CURVEBALL YET.
"""

class RouteInterface(object):
    """
    Utility abstract interface for a route.
    """

    def __init__(self):
        """
        Doesn't do anything.  All functionality is in subclasses.
        """

        pass

    def get_subnet(self):
        """
        Return the subnet of the route.

        Note that a route is assume to be for a single subnet
        """

        raise NotImplementedError("get_subnet not defined")

    def get_gateway(self):
        """
        Return the gateway of the route.

        (how to specify cloning/local routes?)
        """

        raise NotImplementedError("get_gateway not defined")

    def get_iface(self):
        """
        Return the iface for the route.
        """

        raise NotImplementedError("get_iface not defined")

    def is_default(self):
        """
        Is this a default route?
        """

        raise NotImplementedError("is_default not defined")


class RouteTableInterface(object):
    """
    Utility abstract class for routing functions.
    """

    def __init__(self):
        """
        Not meant to be instantiated directly.
        """

    def add_route(self, route):
        """
        Add the given route to the current system routing table

        It is not an error if the route is already present
        """

        raise NotImplementedError("add_route not defined")

    def drop_route(self, route):
        """
        Drop the given route to the current system routing table

        It is not an error if the route is already missing
        """

        raise NotImplementedError("drop_route not defined")

    def set_default(self, route):
        """
        Set the default route in the current system routing table
        """

        raise NotImplementedError("set_default not defined")


if __name__ == '__main__':
    print "No test."
    exit(2)

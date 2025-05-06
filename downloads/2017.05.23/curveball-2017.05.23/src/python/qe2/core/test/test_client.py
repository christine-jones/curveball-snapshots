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
Test scaffolding for a basic quilt client
"""

from twisted.internet import reactor
from twisted.internet.task import LoopingCall

from qe2.core.channel import Qe2SocketClientChannel
from qe2.core.client import Qe2Client
from qe2.core.curveball import Qe2CurveballClientChannel
from qe2.core.curveball import Qe2BadCurveballClientChannel
from qe2.core.params import Qe2Params

def create_curveball(client, local_port_num, decoy='decoy', proto='tls'):
    """
    Create and return a Curveball channel for the given client,
    using the given local port, decoy and protocol
    """

    return Qe2CurveballClientChannel(client,
            local_port_num, decoy, proto)

def create_socket(client):
    """
    Create and return a simple socket channel for the given client
    """

    return Qe2SocketClientChannel(client)

def connect_and_loop(conn, loop_interval):
    """
    Connect the channel, and start a looper running
    """

    conn.connect()
    looper = LoopingCall(conn.pusher)
    conn.set_looper(looper)
    looper.start(loop_interval, now=False)

def test_main():
    """
    Create a client that listens on port 2300 and connects
    to a quilt server at ('quilt', 4000) 
    """

    quilt_host = Qe2Params.get('SERVER_NAME')
    quilt_port = Qe2Params.get('SERVER_LISTEN_PORT')
    client_name = Qe2Params.get('CLIENT_LISTEN_NAME')
    client_port = Qe2Params.get('CLIENT_LISTEN_PORT')

    client = Qe2Client(quilt_host, quilt_port, client_name, client_port)

    conn1 = Qe2CurveballClientChannel(client, 2305, 'decoy', 'tls')
    # conn2 = Qe2BadCurveballClientChannel(client, 2308, 'decoy', 'tls')
    conn2 = Qe2CurveballClientChannel(client, 2308, 'decoy', 'tls')

    connections = set()
    connections.add(conn1)
    connections.add(conn2)

    def poll_status():
        for chan in connections:
            print 'CHANNEL %s %s' % (str(chan), str(chan.transport))

    conn1.max_time = 20
    conn2.max_time = 30

    # conn1 = Qe2SocketClientChannel(client)
    # conn2 = Qe2SocketClientChannel(client)

    connect_and_loop(conn1, 2)
    connect_and_loop(conn2, 2)

    looper = LoopingCall(poll_status)
    looper.start(4, now=False)

    reactor.run()

if __name__ == '__main__':
    test_main()

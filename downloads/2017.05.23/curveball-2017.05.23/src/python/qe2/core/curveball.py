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
Channel endpoint logic for the Curveball channels
"""

import os
import subprocess
import sys
import time

import qe2.core.msg
import qe2.core.socks

from qe2.core.channel import Qe2Channel
from qe2.core.channel import Qe2ChannelWorker
from qe2.core.channel import Qe2SocketServerChannel
from qe2.core.log import QE2LOG
from qe2.core.msg import Qe2Msg

from twisted.internet import reactor
from twisted.internet.protocol import Factory

# We need to know where we were run from, so we
# can find the path to curveball-client.
#
# This is ugly because we could be running this from a
# test script, or from the installation directory.
#
DIRNAME = os.path.normpath(
        os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))
if DIRNAME.endswith(os.path.join('src', 'scripts')):
    CURVEBALL_CLIENT = os.path.join(DIRNAME, 'curveball-client')
elif DIRNAME.endswith(os.path.join('build', 'scripts')):
    CURVEBALL_CLIENT = os.path.join(DIRNAME, 'curveball-client')
else:
    CURVEBALL_CLIENT = os.path.join('/', 'opt', 'curveball',
            'scripts', 'curveball-client')

class Qe2CurveballClientChannel(Qe2Channel):
    """
    A client-side Qe2Channel that connects to an ordinary socket 
    """

    def __init__(self, endpoint, localport, decoy_host, decoy_protocol,
            lifespan=-1):
        """
        svr_host and svr_port are the hostname (or DNS address)
        and port of the quilt server.

        localport is the port to use to connect to the
        Curveball client on localhost.  localport MUST
        be even, and localport+1 is used by the Curveball
        client itself (for clients that need an extra port).

        decoy_host is the name or ipaddr of the decoy host,
        and decoy_protocol is one of "http", "tls", "http-uni",
        "tls-uni", "remora", or "bittorrent".
        """

        Qe2Channel.__init__(self, endpoint, lifespan=lifespan)

        self.max_msg_size = Qe2Msg.MAX_PAYLOAD_LEN

        self.svr_host = endpoint.svr_host
        self.svr_port = endpoint.svr_port

        # TODO: sanity checks on localport.
        #
        self.curveball_port = localport
        self.decoy_host = decoy_host
        self.curveball_internal_port = localport + 1
        self.curveball_protocol = decoy_protocol
        self.curveball_client = None
        self.attempted = False

        if decoy_protocol in ['http', 'http-uni']:
            self.decoy_port = 80
        elif decoy_protocol in ['tls', 'tls-uni']:
            self.decoy_port = 443
        elif decoy_protocol == 'bittorrent':
            self.decoy_port = 6881
        elif decoy_protocol == 'remora':
            pass
        else:
            assert 0, 'Unsupported decoy protocol [%s]' % decoy_protocol

    def connect(self):
        """
        Connect with the other end of this channel.

        This method is usually overloaded by a subclass.
        This implementation is only meant for TCP sockets
        (using Twisted).
        """

        # print 'Qe2SocketClientChannel.connect'

        # Make the curveball connection
        #
        self.curveball_connect()

        self.factory = Factory()
        self.factory.protocol = Qe2ChannelWorker
        self.factory.qe2chan = self

        # print '%s %s' % (str(self.svr_host), str(self.svr_port))

        endpoint = qe2.core.socks.TCP4SocksClientEndpoint(reactor,
                'localhost', self.curveball_port,
                self.svr_host, self.svr_port, timeout=10)

        endpoint.connect(self.factory)

    def disconnect(self):
        """
        Disconnect with the other end of this channel
        """

        QE2LOG.info('DROPPING CURVEBALL CONNECTION')

        # cleanup Curveball-specific stuff
        #
        if self.curveball_client:
            try:
                QE2LOG.info('terminating curveball-client %d',
                        self.curveball_client.pid)
                self.curveball_client.terminate()
                QE2LOG.info('waiting for curveball-client')
                exit_code = self.curveball_client.wait()
                QE2LOG.warn('curveball-client is dead [%d]', exit_code)
            except BaseException, exc:
                QE2LOG.info('curveball-client did not die [%s]',
                        str(exc))

            self.curveball_client = None

        # then call the superclass's disconnect()
        #
        Qe2Channel.disconnect(self)

    def is_connected(self):
        """
        If the Curveball client fails, or is disconnected, then
        the channel is not connected
        """

        if not self.curveball_client:
            return False
        else:
            retcode = self.curveball_client.poll()
            if retcode != None:
                QE2LOG.warn('curveball-client %d exited [%d]',
                        self.curveball_client.pid, retcode)
                self.curveball_client = None
                return False
            return Qe2Channel.is_connected(self)

    def curveball_connect(self):
        """
        Create a Curveball connection that we can use
        to reach the quilt server.

        It is an error (not reliably detected, unfortunately) to
        invoke this twice for the same instance, because the ports
        will collide, so if the connection has been attempted return
        with failure.
        """

        if self.attempted:
            return None
        self.attempted = True

        # TODO: we need the whole, CORRECT path to the curveball client
        # instead of this bogus nonsense

        cb_path = CURVEBALL_CLIENT

        args = list()
        args.append('/usr/bin/sudo') # Only on Posix-like systems
        args.append(cb_path)
        args.append('-p')
        args.append('%d' % self.curveball_port)
        args.append('--tunnel-port')
        args.append('%d' % self.curveball_internal_port)

        args.append('-x')

        if self.curveball_protocol == 'remora':
            args.append('-r')
        else:
            args.append('-d')
            args.append('%s:%d' % (self.decoy_host, self.decoy_port))

            if self.curveball_protocol in ['http', 'http-uni']:
                args.append('-w')

        if self.curveball_protocol in ['http-uni', 'tls-uni']:
            args.append('-u')

        QE2LOG.info('Curveball command [%s]', ' '.join(args))

        self.curveball_client = subprocess.Popen(args, shell=False)

        QE2LOG.info('Curveball subprocess PID [%d]',
                self.curveball_client.pid)

        # Now that we (might) be connected, set the next_ping_time
        #
        self.next_ping_time = time.time() + self.max_idle_time

        return self.curveball_client

    def __del__(self):
        """
        If this reference is lost, or the process exits, then try to
        terminate the curveball-client subprocess
        """

        if self.curveball_client:
            QE2LOG.info('Stopping curveball subprocess')
            self.curveball_client.terminate()


class Qe2BadCurveballClientChannel(Qe2CurveballClientChannel):
    """
    Like Qe2CurveballClientChannel, but with a bad pusher.
    All data recieved is dropped.
    """

    def pusher(self):
        """
        A do nothing pusher: discards its data
        """
        last = self.endpoint.pending_out.last
        avail = last - self.endpoint.next_offset
        if avail > 0:
            # If there's data, we pretend we sent one
            # byte by updating next_offset and ack_send,
            # but we actually don't send anything.
            #
            QE2LOG.info('EMPTY PUSHER: throwing away one byte')
            self.endpoint.next_offset += 1
            self.endpoint.ack_send += 1


class Qe2CurveballServerChannel(Qe2SocketServerChannel):
    """
    A server-side Qe2Channel that uses a twisted transport as its channel

    At this point, the Curveball Server channel is the same as the
    SocketServerChannel, but it may be useful to pull them apart
    later when we want more control over the channel characteristics.
    """

    pass


if __name__ == '__main__':

    def test_curveball_connect():
        """
        Create a CurveballClientChannel and attempt to
        do a connect it to Curveball.
        """

        cb_client = Qe2CurveballClientChannel(
                'quilt', 1080, None, 5010, 'decoy', 'tls')
        cb_client.curveball_connect()

        time.sleep(5)
        print 'Done'

    def test_main():
        test_curveball_connect()

    test_main()

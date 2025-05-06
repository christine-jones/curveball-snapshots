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
The quilt channel manager.

This is a very simple manager, for prototyping purposes.
It is somewhat specialized for Curveball connections.

The descriptor of a channel has several fields:

0. A human-readable name for the channel (for debugging)

1. The class of the channel

2. The parameters passed to the __init__ for the class, as kwargs

3. A reference to the instance for the channel (or None, if the
    channel is not currently instantiated)

4. The polling interval for the channel (when instantiated and running)

"""

import time

from twisted.internet.task import LoopingCall

from qe2.core.log import QE2LOG
from qe2.core.params import Qe2Params

class Qe2ChannelDescriptor(object):

    STATE_LATENT = 0
    STATE_STARTING = 1
    STATE_RUNNING = 2
    STATE_CRASHED = 3

    def __init__(self, name, objclass, kwargs, channel, interval):
        self.name = name
        self.objclass = objclass
        self.kwargs = kwargs
        self.channel = channel
        self.loop_interval = interval

        # If the descriptor is in the starting state, this is the
        # time it entered that state.  Used to determine when a channel
        # has gotten wedged in starting state.
        #
        self.start_time = None

        # The endpoint reference that controls this channel
        #
        self.endpoint = None

    def create(self):
        """
        Instantiate the channel object
        """

        try:
            # The endpoint might not have been created
            # when the descriptor was initialized; make sure
            # that it's initialized now
            #
            self.kwargs['endpoint'] = self.endpoint

            self.channel = self.objclass(**self.kwargs)

        except BaseException, exc:
            QE2LOG.warn('Qe2ChannelDescriptor.create: failed [%s]', str(exc))
            return None
        else:
            return self.channel

    def __str__(self):
        """
        Debugging string representation
        """

        txt = 'Qe2ChannelDescriptor %s ' % self.name
        txt += 'args [%s] ' % str(self.kwargs)
        txt += 'interval [%f] ' % self.loop_interval
        txt += 'channel [%s] ' % str(self.channel)

        return txt


class Qe2ChannelManager(object):
    """
    Track channel use
    """

    def __init__(self, endpoint):

        self.endpoint = endpoint

        self.latent = list()
        self.starting = list()
        self.running = list()

        # TODO: should be a parameter, not magic
        #
        self.max_starting_wait = Qe2Params.get('MAX_CHAN_START_TIME')

        endpoint.register_chanman(self)

    def register(self, descriptor):
        """
        Register a descriptor by appending it to the
        appropriate list: latent, starting, or running
        """

        descriptor.endpoint = self.endpoint

        if not descriptor.channel:
            self.latent.append(descriptor)
        elif descriptor.channel.is_connected():
            self.running.append(descriptor)
        else:
            self.starting.append(descriptor)

    def start_one(self):
        """
        Take a descriptor from the latent list, and attempt
        to start it
        """

        if not self.latent:
            QE2LOG.warn('Qe2ChannelManager.start_one: no latent channels')
            return None

        latent = self.latent[0]
        self.latent = self.latent[1:]

        QE2LOG.info('Qe2ChannelManager.start_one: starting %s', str(latent))

        latent.start_time = time.time()
        self.starting.append(latent)
        channel = latent.create()

        channel.connect()

        looper = LoopingCall(channel.pusher)
        channel.set_looper(looper)
        looper.start(latent.loop_interval, now=True)

        latent.channel = channel

        return channel

    def stop_all(self):
        """
        Stop all channels in the starting or running state, in preparation
        to shutting down the quilt entirely.

        Returns a list of all latent channels, but sets self.latent
        to the empty list in order to avoid a potential race condition
        where new channels are started during the time that old channels
        are stopped
        """

        latent = self.latent
        self.latent = list()

        for desc in self.starting:
            desc.channel.disconnect()
            desc.channel = None
            latent.append(desc)

        for desc in self.running:
            desc.channel.disconnect()
            desc.channel = None
            latent.append(desc)

        self.starting = list()
        self.running = list()

        return latent

    def update(self):
        """
        Update the starting, running, and latent lists to reflect
        the current state of each descriptor.

        The assumption is that instantiated descriptors go from
        starting to running to latent as they get older.  Sometimes,
        however, they get stuck in starting and we have to forcibly
        stop them.
        """

        new_latent = self.latent[:]
        new_starting = list()
        new_running = list()

        now = time.time()

        for desc in self.starting:
            if desc.channel.is_connected():
                desc.start_time = None
                self.running.append(desc)
            elif (now - desc.start_time) > self.max_starting_wait:
                QE2LOG.warn('killing channel stuck in start')
                desc.channel.disconnect()
                new_latent.append(desc)
            else:
                QE2LOG.warn('channel lingering in start state')
                new_starting.append(desc)

        for desc in self.running:
            if desc.channel.is_connected():
                new_running.append(desc)
            else:
                QE2LOG.info('a channel has been lost')
                new_latent.append(desc)

        self.latent = new_latent
        self.starting = new_starting
        self.running = new_running

    def __str__(self):

        now = time.time()
        txt = 'Qe2ChannelManager state: '

        for desc in self.latent:
            txt += 'latent [%s] / ' % desc.name

        for desc in self.starting:
            txt += 'starting [%.2f] [%s] / ' % (
                    now - desc.start_time, desc.name)

        for desc in self.running:
            txt += 'running [%s] / ' % desc.name

        return txt


if __name__ == '__main__':
    from twisted.internet import reactor

    from qe2.core.channel import Qe2SocketClientChannel
    from qe2.core.client import Qe2Client
    from qe2.core.curveball import Qe2CurveballClientChannel

    def test_main():

        quilt_host = Qe2Params.get('SERVER_NAME')
        quilt_port = Qe2Params.get('SERVER_LISTEN_PORT')
        client_name = Qe2Params.get('CLIENT_LISTEN_NAME')
        client_port = Qe2Params.get('CLIENT_LISTEN_PORT')

        client = Qe2Client(quilt_host, quilt_port, client_name, client_port)

        man = Qe2ChannelManager(client)

        desc0 = Qe2ChannelDescriptor('desc0 sock',
                Qe2SocketClientChannel, {'lifespan' : 20}, None, 1)

        desc1 = Qe2ChannelDescriptor('desc1 sock',
                Qe2SocketClientChannel, {'lifespan' : 20}, None, 1)

        desc2 = Qe2ChannelDescriptor('desc2 sock',
                Qe2SocketClientChannel, {'lifespan' : 20}, None, 1)

        desc3 = Qe2ChannelDescriptor('desc3 sock',
                Qe2SocketClientChannel, {'lifespan' : 20}, None, 1)

        desc4 = Qe2ChannelDescriptor('desc4 cb decoy:443',
                Qe2CurveballClientChannel,
                { 'localport' : 2310, 'decoy_host' : 'decoy',
                    'decoy_protocol' : 'tls', 'lifespan' : 15},
                None, 0.01)

        desc5 = Qe2ChannelDescriptor('desc5 cb decoy:443',
                Qe2CurveballClientChannel,
                { 'localport' : 2315, 'decoy_host' : 'decoy',
                    'decoy_protocol' : 'tls', 'lifespan' : 15},
                None, 0.01)

        # man.register(desc0)
        # man.register(desc1)
        # man.register(desc2)
        man.register(desc4)
        man.register(desc5)

        def nudger():

            man.update()

            QE2LOG.info('running %d starting %d latent %d',
                    len(man.running), len(man.starting), len(man.latent))
            QE2LOG.debug(str(man))

            if len(man.running) == 0:
                QE2LOG.warn('no channels running: starting latent channel')
                man.start_one()

        looper = LoopingCall(nudger)
        looper.start(5, now=True)

        reactor.run()

    test_main()

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
The Decoy Router (DR) side of the DR2DP interface.
"""

import logging
import os
import socket
import struct

from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor
from twisted.internet import error

from cb.dr2dp.dr2dp import DR2DPMessage1
from cb.dr2dp.dr2dp import DR2DPMessageSentinelFilter
from cb.dr2dp.dr2dp import DR2DPMessageRedirectFlow
from cb.dr2dp.dr2dp import DR2DPMessageRemoveFlow
from cb.dr2dp.dr2dp import DR2DPMessageTLSFlowEstablished
from cb.dr2dp.dr2dp import DR2DPMessageICMP

from cb.util.dir_watcher import DirWatcher

from cb.dr2dp.bloom_watcher import BloomWatcherHelper
from cb.dr2dp.dh_watcher import BadDecoyWatcherHelper


class DstProtocol(Protocol):
    """
    DP endpoint of a DR2DP connection.
    """

    def __init__(self):
        self.log = logging.getLogger('dr2dp.dr')
        self.raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                                 socket.IPPROTO_TCP)
        self.raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.recv_buffer = ''

        # Initialize the jump tables used to dispatch message processors.
        # These can be modified in subclasses, but subclasses will pick up their
        # own versions of these methods, so this shouldn't be necessary.
        self.optype_req2handler = {
            DR2DPMessage1.OP_TYPE_PING : self.req_ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.req_forward_ip,
            DR2DPMessage1.OP_TYPE_SENTINEL_FILTER : self.req_unimplemented,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.req_unimplemented,
            DR2DPMessage1.OP_TYPE_REMOVE_FLOW : self.req_remove_flow,
            DR2DPMessage1.OP_TYPE_REASSIGN_FLOW : self.req_unimplemented,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.req_unimplemented,
            DR2DPMessage1.OP_TYPE_ICMP : self.req_unimplemented,
            DR2DPMessage1.OP_TYPE_DH_BLACKLIST : self.req_unimplemented
        }

        self.optype_rep2handler = {
            DR2DPMessage1.OP_TYPE_PING : self.res_ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.res_forward_ip,
            DR2DPMessage1.OP_TYPE_SENTINEL_FILTER : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REMOVE_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REASSIGN_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_ICMP : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_DH_BLACKLIST : self.res_unimplemented
        }

        # Reference to the click interface.
        #self.src_handler = None

    def connectionLost(self, reason):
        """
        If we lose the connection to the DP, then we gripe and give up.

        TODO: try to reconnect.
        """

        print 'Lost connection with DP'

        try:
            reactor.stop()
        except error.ReactorNotRunning:
            pass
        except:
            sys.exit(1)

    def dataReceived(self, new_data):
        self.recv_buffer += new_data

        # It's possible for more than one message to come in as part
        # of one read, at least in theory.  Therefore we consume as
        # much of the buffer as possible, not just the first message.
        #
        while 1:
            # print 'LEN %d' % len(self._recv_buffer)
            (msg, self.recv_buffer) = DR2DPMessage1.recv_from_buffer(
                    self.recv_buffer)
            if msg != None:
                self.handle_msg(msg)
            else:
                break

    def handle_msg(self, msg):
        """
        Handle an incoming DR2DP message.

        Calls the right handler for the combination of request/response and
        operation type.  If you get an exception because the dispatch tables are
        not defined, it's because you should have defined them in a subclass.
        """

        if msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_REQUEST:
            if not msg.op_type in self.optype_req2handler:
                self.log.info("no handler for %s" % msg)
                handler = self.unimplemented_request
            else:
                handler = self.optype_req2handler[msg.op_type]
        elif msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_RESPONSE:
            if not msg.op_type in self.optype_rep2handler:
                self.log.info("no handler for %s" % msg)
                handler = self.unimplemented_response
            else:
                handler = self.optype_rep2handler[msg.op_type]
        else:
            # TODO - yoicks!
            self.log.warn("DR2DPWorker bad msg type %s" % msg)
            return False

        return handler(msg)

    def forward_message(self, msg):
        """
        Forward DR2DP message to Decoy Proxy.
        """
        #print 'forwarding to DP'
        self.transport.write(msg.pack())

    def req_ping(self, msg):
        """
        Handle a ping request
        """

        # We reuse the msg object, after fiddling with some of its fields
        #
        msg.msg_type = DR2DPMessage1.MESSAGE_TYPE_RESPONSE
        packed_msg = msg.pack('Ping response')
        self.transport.write(packed_msg)
        
    def res_ping(self, msg):
        """
        Handle a ping response
        """

        self.log.info('ping response (%s)' % (str(msg),))
        return True        
    
    def res_forward_ip(self, msg):
        """
        Handle a forward_ip response
        """

        self.log.info('forward_ip response (%s)' % msg)
        return True    
    
    def req_forward_ip(self, msg):
        """
        Handle a forward_ip request.
        """
        if self.factory.src_protocol:
            self.factory.src_protocol.forward_message(msg)


        return True

    def req_remove_flow(self, msg):
        """
        Handle a remove_flow request.
        """
        msg.__class__ = DR2DPMessageRemoveFlow
        try:
            msg.unpack()
        except:
            self.log.warn('invalid remove_flow message')
            return
        
        if self.factory.src_protocol:
            self.factory.src_protocol.forward_message(msg)

    def req_unimplemented(self, msg):
        """
        Catch-all for the unimplemented requests

        NOTE that we do not differentiate between requests that are illegal and
        requests that are unimplemented. TODO: we should differentiate these.
        """

        # TODO: log this, not print
        print 'unimplemented request (%s)' % (str(msg),)

    def res_unimplemented(self, msg):
        """
        Catch-all for the unimplemented responses

        NOTE that we do not differentiate between responses that are illegal and
        responses that are unimplemented.
        """

        # TODO: log this, not print
        print 'unimplemented response (%s)' % (str(msg),)


class SrcProtocol(Protocol):
    """
    Handles data received on a unix socket.
    """

    def __init__(self):

        self.log = logging.getLogger('dr2dp.dr')
        #self.dp_interface = None
        self.buff = ''

        self.optype_req2handler = {
            DR2DPMessage1.OP_TYPE_PING : self.ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.forward_ip,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.redirect_flow,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.tls_flow,
            DR2DPMessage1.OP_TYPE_ICMP : self.icmp,
            DR2DPMessage1.OP_TYPE_DH_BLACKLIST : self.handle_dh_blacklist,
        }

    def connectionMade(self):
        #self.dp_interface = self.factory.dst_protocol
        #self.dp_interface.register_src(self)
        self.factory.dr2dp_dr.src_connected(self)

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        """
        Read data from Click DR and pass it to the Decoy Proxy.
        """

        self.buff += data
        while 1:
            (msg, self.buff) = DR2DPMessage1.recv_from_buffer(self.buff)
            if msg != None:
                self.handle_msg(msg)
            else:
                break

    def handle_msg(self, msg):
        """
        Handle an incoming DR2DP message.
        """

        if msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_REQUEST:
            if not msg.op_type in self.optype_req2handler:
                self.log.info("no handler for %s" % msg)
                handler = self.unimplemented_request
            else:
                handler = self.optype_req2handler[msg.op_type]
        else:
            self.log_warn("DR2DP invalid message %s" % msg)
            return False

        return handler(msg)

    def forward_message(self, msg):
        self.transport.write(msg.pack())

    def upload_sentinel_filter(self, hash_size, salts=None):
        self.forward_message(DR2DPMessageSentinelFilter(hash_size, salts))

    def upload_dh_blacklist(self):
        self.forward_message(DR2DPMessage1(
                                 DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                                 DR2DPMessage1.OP_TYPE_DH_BLACKLIST))

    def ping(self, msg):
        msg.msg_type = DR2DPMessage1.MESSAGE_TYPE_RESPONSE
        self.transport.write(msg.pack('Ping response'))
        return True

    def forward_ip(self, msg):

        msg.get_5tuple()

        if self.factory.dst_protocol:
            self.factory.dst_protocol.forward_message(msg)
        #self.dp_interface.forward_message(msg)
        return True

    def redirect_flow(self, msg):
        msg.__class__ = DR2DPMessageRedirectFlow
        try:
            msg.unpack()
        except:
            self.log.warn('invalid redirect_flow message')
            return False
        if self.factory.dst_protocol:
            self.factory.dst_protocol.forward_message(msg)
        #self.dp_interface.forward_message(msg)
        return True

    def tls_flow(self, msg):
        msg.__class__ = DR2DPMessageTLSFlowEstablished
        try:
            msg.unpack()
        except:
            self.log.warn('invalid tls_flow message')
            return False

        if self.factory.dst_protocol:
            self.factory.dst_protocol.forward_message(msg)        
        #self.dp_interface.forward_message(msg)
        return True

    def icmp(self, msg):
        msg.__class__ = DR2DPMessageICMP
        try:
            msg.unpack()
        except:
            self.log.warn('invalid icmp message')
            return False

        if self.factory.dst_protocol:
            self.factory.dst_protocol.forward_message(msg)

    def handle_dh_blacklist(self, msg):
        """
        A DH blacklist message should never be received, only generated.
        """
        self.log.warn('error --- received DH blacklist message')
        return

    def unimplemented_request(self, msg):
        self.log.info('unimplemented DR2DP request (%s)' % (str(msg),))
        return True

    
class DR2DP_DR(object):
    def __init__(self, dp_addr, dr_socket, dst_connected_callback=None,
            enable_watchers=False):
        """
        If enable_watchers is True, then start file watchers for the
        Bloom filter and Bad Decoy Host filter files.

        We only want one DR2DP_DR (or possibly none, in special cases)
        to start a set of file watchers; we don't want multiple messages
        to be sent to the DR to load new files when they become available.
        Because we don't want this to happen until all the DP connections
        are connected, enable_watchers should only be True for the last
        DR2DP_DR created for this DR.
        """

        self.log = logging.getLogger('dr2dp.dr')
        self.dr_socket = dr_socket

        self.dst_connected_callback = dst_connected_callback
        self.enable_watchers = enable_watchers
        #self.dst_protocol = None

        # Connect to the dst (DR2DP_DP)
        self.dstFactory = Factory()
        self.dstFactory.protocol = DstProtocol
        self.dstFactory.dr2dp_dr = self
        self.dstFactory.src_protocol = None
        
        endpoint = endpoints.TCP4ClientEndpoint(reactor, dp_addr[0], dp_addr[1])
        d = endpoint.connect(self.dstFactory)
        d.addCallback(self.dst_connected)
        d.addErrback(self.dst_failed)

        # Connect to the src (DR)
        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory.dr2dp_dr = self
        self.srcFactory.dst_protocol = None
    
        # Remove previous instance of socket if it already exists.
        if os.path.exists(self.dr_socket):
            os.remove(self.dr_socket)
        print 'starting socket [%s]' % self.dr_socket
        endpoint = endpoints.UNIXServerEndpoint(reactor, self.dr_socket)
        endpoint.listen(self.srcFactory)  
        if self.dst_connected_callback:
            # Let anyone that wants to know that we've connected to the
            # destination and that the unix socket is up and ready
            self.dst_connected_callback()         
        
    
    def dst_connected(self, protocol):
        self.srcFactory.dst_protocol = protocol        

    def dst_failed(self, protocol):
        print 'Failed to connect to DP [%s]' % self.dr_socket
        try:
            reactor.stop()
        except error.ReactorNotRunning:
            pass
        except:
            sys.exit(1)

    def src_connected(self, protocol):
        self.dstFactory.src_protocol = protocol

        print 'Connected to Unix Socket [%s]' % self.dr_socket

        if self.enable_watchers:
            helper = BloomWatcherHelper(protocol.upload_sentinel_filter)
            self.dir_watcher = DirWatcher('/tmp/dr/bloomfilters/', helper, 5)

            baddh_helper = BadDecoyWatcherHelper(protocol.upload_dh_blacklist)
            self.baddh_watcher = DirWatcher('/tmp/dr/baddh/', baddh_helper, 5)


class DR2DPS_DR(DR2DP_DR):
    """
    A generalized DR2DP that can handle multiple DPs at
    different locations.
    """

    def __init__(self, dp_locs, dr_socket, dst_connected_callback=None):
        self.log = logging.getLogger('dr2dp.dr')
        self.dr_socket = dr_socket
        self.conn_cnt = 0

        self.dst_connected_callback = dst_connected_callback

        self.conns = [ None ] * len(dp_locs)

        for i in xrange(len(dp_locs)):
            (dp_addr, dp_port) = dp_locs[i]

            self.conns[i] = Factory()
            self.conns[i].protocol = DstProtocol
            self.conns[i].protocol.index = i
            self.conns[i].dr2dp_dr = self
            self.conns[i].src_protocol = None

            endpoint = endpoints.TCP4ClientEndpoint(
                    reactor, dp_addr, dp_port)
            d = endpoint.connect(self.conns[i])
            d.addCallback(self.dst_connected)
            d.addErrback(self.dst_failed)

        # Connect to the src (DR)
        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory.dr2dp_dr = self
        self.srcFactory.dst_protocol = None

        # Remove previous instance of socket if it already exists.
        if os.path.exists(self.dr_socket):
            os.remove(self.dr_socket)

        print "starting socket"
        endpoint = endpoints.UNIXServerEndpoint(reactor, self.dr_socket)
        endpoint.listen(self.srcFactory)  
        if self.dst_connected_callback:
            # Let anyone that wants to know that we've connected to the
            # destination and that the unix socket is up and ready
            self.dst_connected_callback()         

    def dst_connected(self, protocol):
        self.srcFactory.dst_protocol = protocol        
        print 'connected to DP %s' % protocol.index

    
def main():
    import optparse

    def parse_args():
        parser = optparse.OptionParser()
        parser.add_option("--addr", dest="addr", default="127.0.0.1",
                          metavar="IPADDR",
                          help="IP address to connect to Decoy Proxy. "
                               "Defaults to 127.0.0.1.")
        parser.add_option("--port", dest="port", type="int", default="4001",
                          metavar="PORT",
                          help="Port to connect to Decoy Proxy. "
                               "Defaults to 4001.")
        parser.add_option("--socket", dest="socket", default="/tmp/curveball",
                          metavar="FILENAME",
                          help="Unix domain socket filename. "
                               "Defaults to '/tmp/curveball.'")

        (opts, args) = parser.parse_args()
        return opts

    opts = parse_args()
    dr2dp_dr = DR2DP_DR((opts.addr, opts.port), opts.socket, None, False)

    reactor.run()


if __name__ == '__main__':
    exit(main())

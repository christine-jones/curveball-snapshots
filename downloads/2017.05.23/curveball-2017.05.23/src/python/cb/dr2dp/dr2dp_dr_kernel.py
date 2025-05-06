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
import optparse
import os
import socket
import struct

from zope.interface import implements
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor, IWriteDescriptor
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints

from cb.dr2dp.dr2dp import DR2DPMessage1
from cb.dr2dp.dr2dp import DR2DPMessageSentinelFilter
from cb.dr2dp.dr2dp import DR2DPMessageRedirectFlow
from cb.dr2dp.dr2dp import DR2DPMessageRemoveFlow
from cb.dr2dp.dr2dp import DR2DPMessageTLSFlowEstablished

from cb.util.dir_watcher import DirWatcher

from cb.dr2dp.bloom_watcher import BloomWatcherHelper


class DstProtocol(Protocol):
    """
    DR endpoint of a DR2DP connection.
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
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.req_unimplemented
        }

        self.optype_rep2handler = {
            DR2DPMessage1.OP_TYPE_PING : self.res_ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.res_forward_ip,
            DR2DPMessage1.OP_TYPE_SENTINEL_FILTER : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REMOVE_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_REASSIGN_FLOW : self.res_unimplemented,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.res_unimplemented
        }

        # Reference to the Click inteface.
        self.click_interface = None

    def register_click_interface(self, interface):
        self.click_interface = interface

    def forward_message(self, msg):
        """
        Forward DR2DP message to Decoy Proxy.
        """
        self.transport.write(msg.pack())

    def dataReceived(self, new_data):
        self.recv_buffer += new_data

        # It's possible for more than one message to come in as part
        # of one read, at least in theory.  Therefore we consume as
        # much of the buffer as possible, not just the first message.
        while 1:
            (msg, self.recv_buffer) = DR2DPMessage1.recv_from_buffer(
                                                        self.recv_buffer)
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
        elif msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_RESPONSE:
            if not msg.op_type in self.optype_rep2handler:
                self.log.info("no handler for %s" % msg)
                handler = self.unimplemented_response
            else:
                handler = self.optype_rep2handler[msg.op_type]
        else:
            self.log.warn("DR2DPWorker bad msg type %s" % msg)
            return False

        return handler(msg)

    def req_ping(self, msg):
        msg.msg_type = DR2DPMessage1.MESSAGE_TYPE_RESPONSE
        self.transport.write(msg.pack('Ping response'))
        return True

    def res_ping(self, msg):
        self.log.info('ping response (%s)' % (str(msg),))
        return True

    def req_forward_ip(self, msg):
        """
        Send a packet to the Click DR to be forwarded.
        """
        if self.click_interface != None:
            self.click_interface.send_msg_to_dr(msg.pack())

        return True

    def res_forward_ip(self, msg):
        self.log.info('forward_ip response (%s)' % msg)
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

        if self.click_interface != None:
            self.click_interface.send_msg_to_dr(msg.pack())

    def req_unimplemented(self, msg):
        self.log.info('unimplemented request (%s)' % (str(msg),))
        return True

    def res_unimplemented(self, msg):
        self.log.info('unimplemented response (%s)' % (str(msg),))
        return True


class ClickInterfaceRd:
    implements(IReadDescriptor)
    def __init__(self, device_rd, device_wr, protocol):
        self.log = logging.getLogger('dr2dp.dr')
        self.buff = ''
        self.dp_interface = protocol
        self.dp_interface.register_click_interface(self)

        self.optype_req2handler = {
            DR2DPMessage1.OP_TYPE_PING : self.ping,
            DR2DPMessage1.OP_TYPE_FORWARD_IP : self.forward_ip,
            DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.redirect_flow,
            DR2DPMessage1.OP_TYPE_TLS_FLOW_ESTABLISHED : self.tls_flow,
        }

        try:
            self.rd_fd = os.open(device_rd, os.O_RDONLY | os.O_NONBLOCK)
            # Note: blocking write, assume this devicewon't block
            self.wr_fd = os.open(device_wr, os.O_WRONLY)
            print "Connected to kernel"
        except os.error:
            print "Failed to connect to kernel"
            self.rd_fd = -1
            self.wr_fd = -1
            self.log.warn("failed to open click device")
            return

        reactor.addReader(self)

    def doRead(self):
        self.buff += os.read(self.rd_fd, 65536)

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

    def ping(self, msg):
        msg.msg_type = DR2DPMessage1.MESSAGE_TYPE_RESPONSE
        self.send_msg_to_dr(msg.pack('Ping response'))
        return True

    def forward_ip(self, msg):
        self.dp_interface.forward_message(msg)
        return True

    def redirect_flow(self, msg):
        msg.__class__ = DR2DPMessageRedirectFlow
        try:
            msg.unpack()
        except:
            self.log.warn('invalid redirect_flow message')
            return

        self.dp_interface.forward_message(msg)
        return True

    def tls_flow(self, msg):
        msg.__class__ = DR2DPMessageTLSFlowEstablished
        try:
            msg.unpack()
        except:
            self.log.warn('invalid tls_flow message')
            return False

        self.dp_interface.forward_messgae(msg)
        return True

    def unimplemented_request(self, msg):
        self.log.info('unimplemented DR2DP request (%s)' % (str(msg),))
        return True

    def upload_sentinel_filter(self, hash_size, salts=None):
        self.send_msg_to_dr(DR2DPMessageSentinelFilter(hash_size, salts).pack())

    def send_msg_to_dr(self, pkt):
        if self.wr_fd >= 0:
            os.write(self.wr_fd, pkt)

    def fileno(self):
        return self.rd_fd

    def logPrefix(self):
        return 'DR2DP DR Click Interface'

    def connectionLost(self, reason):
        self.rd_fd = -1
        self.log.warn('click connection lost')

    def __del__(self):
        reactor.removeReader(self)
        if self.rd_fd >= 0:
            try:
                os.close(self.rd_fd)
            except OSError:
                pass
        if self.wr_fd >= 0:
            try:
                os.close(self.wr_fd)
            except OSError:
                pass            


class DR2DP_DR(object):
    def __init__(self, dp_addr, rd_device, wr_device):
        self.log = logging.getLogger('dr2dp.dr')
        self.rd_device = rd_device
        self.wr_device = wr_device

        # Connect to DR2DP_DP
        self.dstFactory = Factory()
        self.dstFactory.protocol = DstProtocol
        self.dstFactory.dr2dp_dr = self
        self.dst_protocol = None

        endpoint = endpoints.TCP4ClientEndpoint(reactor, dp_addr[0], dp_addr[1])
        d = endpoint.connect(self.dstFactory)
        d.addCallback(self.dst_connected)
    
    def dst_connected(self, protocol):
        # Connect to DR
        self.dst_protocol = protocol
        self.click = ClickInterfaceRd(self.rd_device, self.wr_device, protocol)
        helper = BloomWatcherHelper(self.click.upload_sentinel_filter)

        self.dir_watcher = DirWatcher('/tmp/dr/bloomfilters/', helper, 5)


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
    parser.add_option("--rddevice", dest="rd_device",
                      default="/dev/click_user0",
                      metavar="FILENAME",
                      help="Click read device filename. "
                           "Defaults to '/dev/click_user0.'")
    parser.add_option("--wrdevice", dest="wr_device",
                      default="/dev/click_user1",
                      metavar="FILENAME",
                      help="Click write device filename. "
                           "Defaults to '/dev/click_user1.'")

    (opts, args) = parser.parse_args()
    return opts


def main():
    opts = parse_args()
    dr2dp_dr = DR2DP_DR((opts.addr, opts.port),
            opts.rd_device, opts.wr_device, False)
    reactor.run()


if __name__ == '__main__':
    exit(main())

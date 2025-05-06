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
Prototype of the DP DR2DP endpoint.
"""
import logging
import optparse
import struct
from twisted.internet.protocol import Factory, Protocol
import twisted.internet.endpoints as endpoints
from twisted.internet import reactor


from cb.dr2dp.dr2dp import DR2DPMessage1
from cb.dr2dp.dr2dp import DR2DPMessageRedirectFlow
from cb.dr2dp.dr2dp import DR2DPMessageRemoveFlow
from cb.dr2dp.dr2dp import DR2DPMessageICMP
import sys

import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))
# FIXME -- replace DEBUG and log_debug(...) with self.log.debug(...)
def log_debug(msg):
    print >> sys.stderr, 'DR2DP_DP: %s' % msg

# FIXME -- replace log_warn with self.log.warn
def log_warn(msg):
    print >> sys.stderr, 'DR2DP_DP(warning): %s' % msg

# FIXME -- replace log_info with self.log.info
def log_info(msg):
    print >> sys.stderr, 'DR2DP_DP(info): %s' % msg

class SrcProtocol(Protocol):
    """
    Implementation of a DR2DP DP endpoint
    """

    def __init__(self):
        # Initialize the jump tables used to dispatch message processors.
        # These can be modified in subclasses, but subclasses will pick up their
        # own versions of these methods, so this shouldn't be necessary.
        #
        self.optype_req2handler = {
                DR2DPMessage1.OP_TYPE_PING : self.req_ping,
                DR2DPMessage1.OP_TYPE_FORWARD_IP : self.req_forward_ip,
                DR2DPMessage1.OP_TYPE_REDIRECT_FLOW : self.req_redirect_flow,
                DR2DPMessage1.OP_TYPE_ICMP : self.req_icmp,
            }

        self.optype_rep2handler = {
                DR2DPMessage1.OP_TYPE_PING : self.res_ping,
                DR2DPMessage1.OP_TYPE_FORWARD_IP : self.res_forward_ip,
            }

        # Reference to the connection monitor
        self.dp_recv_endpoint = None
        self.dp_redirect_flow = None
        self.dp_icmp_handler = None
        
        self.recv_buffer = ''
        self.log = logging.getLogger('dr2dp.dp')
        DEBUG and log_debug('SrcProtocol.__init__')

    def connectionMade(self):
        DEBUG and log_debug('SrcProtocol.connectionMade')
        self.dp_recv_endpoint = self.factory.dr2dp_dp.dp_recv_endpoint
        self.dp_redirect_flow = self.factory.dr2dp_dp.dp_redirect_flow
        self.dp_icmp_handler = self.factory.dr2dp_dp.dp_icmp_handler
        
        self.factory.dr2dp_dp.srcConnected(self)
        
    def connectionLost(self, reason):
        # TODO: Tell the con mon to shut down
        # all state for this dr2dp link
        DEBUG and log_debug('SrcProtocol.connectionLost: %s' % reason)
        pass

    def dataReceived(self, new_data):
        DEBUG and log_debug('SrcProtocol.dataReceived(%d bytes)' % len(new_data))
        
        self.recv_buffer += new_data
        #print 'got something from DR!'
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
        not defined, it's because you should have defined them!
        """

        DEBUG and log_debug('SrcProtocol.handle_msg')
        if msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_REQUEST:
            if not msg.op_type in self.optype_req2handler:
                log_info("no handler for %s" % msg)
                handler = self.unimplemented_request
            else:
                handler = self.optype_req2handler[msg.op_type]

        elif msg.msg_type == DR2DPMessage1.MESSAGE_TYPE_RESPONSE:
            if not msg.op_type in self.optype_rep2handler:
                log_info("no handler for %s" % msg)
                handler = self.unimplemented_response
            else:
                handler = self.optype_rep2handler[msg.op_type]
        else:
            # TODO - yoicks!
            log_warn("Bad msg type %s" % msg)
            return False

        return handler(msg)    
        

    def send_to_dr(self, pkt):
        """
        Forward the given pkt via the DR.

        If pkt isn't a str or buffer, things are going to behave oddly.
        """

        DEBUG and log_debug('SrcProtocol.send_to_dr')
        msg = DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                DR2DPMessage1.OP_TYPE_FORWARD_IP)
 
        self.transport.write(msg.pack(pkt))

    def send_remove_flow(self, src_addr, dst_addr,
                               src_port, dst_port, protocol):
        """
        Send a remove flow notification to the DR.
        """

        DEBUG and log_debug('SrcProtocol.send_remove_flow')

        msg = DR2DPMessageRemoveFlow(src_addr, dst_addr,
                                     src_port, dst_port, protocol)
        self.transport.write(msg.pack())

    def req_ping(self, msg):
        """
        Handle a ping request
        """

        DEBUG and log_debug('SrcProtocol.req_ping')
        # We reuse the msg fiddling with some of its fields
        #
        msg.msg_type = DR2DPMessage1.MESSAGE_TYPE_RESPONSE
        packed_msg = msg.pack('Ping response')
        self.transport.write(packed_msg)

    def req_redirect_flow(self, msg):
        DEBUG and log_debug('SrcProtocol.req_redirect_flow')
        msg.__class__ = DR2DPMessageRedirectFlow
        try:
            msg.unpack()
        except:
            log_warn('invalid redirect_flow message')
            return

        opts = msg.syn_tcp_options
        buf_pkts = msg.sentinel_packets
        pkts = []
        index = 0
        while True:
            l = struct.unpack('!H', buf_pkts[index+2:index+4])[0]
            pkts.append(buf_pkts[index:index+l])
            index = index+l
            if index >= len(buf_pkts):
                break
            
            
        self.dp_redirect_flow(pkts, opts, self)
        
        return True
    
    def req_forward_ip(self, msg):
        """
        Handle a forward_ip request
        """

        DEBUG and log_debug('SrcProtocol.req_forward_ip')
        if self.dp_recv_endpoint == None:
            # WHOOPS: no connection monitor yet.  We don't know what to do.
            # 
            # If we don't know what to do, then we just push it back to the DR
            # (and hope it doesn't boomerang back at us).
            #
            DEBUG and log_debug('no connection_monitor yet: sending back to DR')
            self.send_to_dr(msg.data)
        else:
            self.dp_recv_endpoint(msg.data)

        return True

    def req_icmp(self, msg):
        """
        Handle an icmp request
        """

        DEBUG and log_debug('SrcProtocol.req_icmp')
        msg.__class__ = DR2DPMessageICMP
        try:
            msg.unpack()
        except:
            log_warn('invalid icmp message')
            return False

        if self.dp_icmp_handler != None:
            self.dp_icmp_handler(msg.get_tuple(),
                                 msg.get_pkt(),
                                 msg.is_reverse())
        else:
            DEBUG and log_debug('no icmp handler registered')
 
        return True

    def res_ping(self, msg):
        """
        Handle a ping response
        """

        log_info('ping response (%s)' % (str(msg),))
        return True

    def res_forward_ip(self, msg):
        """
        Handle a forward_ip response
        """

        # For a TCP session, we don't expect these

        log_info('forward_ip response (%s)' % (str(msg),))
        return True


class DR2DP_DP(object):
    """
    DP side of DR2DP
    """
    
    def __init__(self, srcaddr):
        self.dp_recv_endpoint = None
        self.dp_redirect_flow = None
        self.dp_icmp_handler = None

        self.srcFactory = Factory()
        self.srcFactory.protocol = SrcProtocol
        self.srcFactory.dr2dp_dp = self
        
        endpoint = endpoints.TCP4ServerEndpoint(reactor, srcaddr[1], interface=srcaddr[0])
        endpoint.listen(self.srcFactory)
        self.log = logging.getLogger('dr2dp.dp')
    
    def register_dp_recv(self, dp_recv_end, dp_redirect_flow, dp_icmp_handler):
        DEBUG and log_debug('DR2DP_DP.register_recv_from_dr')
        self.dp_recv_endpoint = dp_recv_end
        self.dp_redirect_flow = dp_redirect_flow
        self.dp_icmp_handler = dp_icmp_handler
        self.srcFactory.dp_recv_endpoint = dp_recv_end
        self.srcFactory.dp_redirect_flow = dp_redirect_flow
        self.srcFactory.dp_icmp_handler = dp_icmp_handler
    
    def srcConnected(self, protocol):
        DEBUG and log_debug('DR2DP_DP.srcConnected')
        self.src_protocol = protocol
        
    def send_to_dr(self, pkt):
        DEBUG and log_debug('DR2DP_DP.send_to_dr')
        if self.src_protocol:
            self.src_protocol.send_to_dr(pkt)

    def send_remove_flow(self, src_addr, dst_addr,
                               src_port, dst_port, protocol):
        DEBUG and log_debug('DR2DP_DP.send_remove_flow')
        if self.src_protocol:
            self.src_protocol.send_remove_flow(src_addr, dst_addr,
                                               src_port, dst_port, protocol)


if __name__ == '__main__': # TEST MAIN
    import threading
    import time

    class TestDriver(threading.Thread):
        """
        Test driver that injects some messages into the given sock
        """

        def __init__(self, sock):
            threading.Thread.__init__(self)
            self.sock = sock

        def run(self):
            """
            Pause, then inject messages into self.sock
            """

            dummy_payload = '0123456789abcdefghijklmnopqrstuv' * (8 * 32)
            curr_data = ''

            target_MB_per_sec = 10 * 1024 * 1024.0
            min_sleep = 1.0 # minimum pause time

            time.sleep(1.0)

            print 'STARTING'
            while 1:

                # I'm intentionally cramming more than one message into a single
                # send in order to make sure that the correct thing happens when
                # a single recv captures more than one msg, and a single recv
                # might contain only a fraction of a message.

                curr_data += dummy_payload

                print "curr_data len %d" % len(curr_data)

                msgs = []

                msgs.append(DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                        DR2DPMessage1.OP_TYPE_PING).pack(curr_data))
                msgs.append(DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                        DR2DPMessage1.OP_TYPE_PING).pack(curr_data))
                msgs.append(DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                        DR2DPMessage1.OP_TYPE_PING).pack(curr_data))
                msgs.append(DR2DPMessage1(DR2DPMessage1.MESSAGE_TYPE_REQUEST,
                        DR2DPMessage1.OP_TYPE_PING).pack(curr_data))

                packed_bytes = ''.join(msgs)
                len_packed_bytes = len(packed_bytes)

                third = len_packed_bytes / 3
                print third

                first_part = packed_bytes[:third]
                second_part = packed_bytes[third:2 * third]
                last_part = packed_bytes[2 * third:]

                self.sock.transport.write(first_part)
                self.sock.transport.write(second_part)
                self.sock.transport.write(last_part)

                # make it clear to the gc that it can reuse this space right
                # away.
                packed_bytes = ''
                msgs = []

                drain_delay = len_packed_bytes / target_MB_per_sec
                if drain_delay < min_sleep:
                    drain_delay = min_sleep

                print "drain delay = %fs len %d" % (drain_delay,
                        len_packed_bytes)
                print "snoozing"
                time.sleep(drain_delay)
                print "awake"


    def client_connected(protocol):
        print 'client connected'
        client_thread = TestDriver(protocol)
        client_thread.start()
        

    def test_main(opts):
        server = DR2DP_DP(('', 4000))

        clientFactory = Factory()
        clientFactory.protocol = Protocol
        endpoint = endpoints.TCP4ClientEndpoint(reactor, '127.0.0.1', 4000)
        d = endpoint.connect(clientFactory)
        d.addCallback(client_connected)
        reactor.run()
        
    def parse_args():
        parser = optparse.OptionParser()
        
        parser.add_option("-p", "--port", default="4001",
                          metavar="FILENAME",
                          help="Port to listen on from DR2DP_DR")
    
        (opts, args) = parser.parse_args()
        return opts        
    
    exit(test_main(opts))


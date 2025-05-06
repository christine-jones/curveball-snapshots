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


from asyncorebbn import asyncore

import socket
import sys
import os.path

sys.path.append('../../../')
sys.path.append('../../../nfqueue/')


import dpkt
import dumbnet as dnet

import cb.util.cblogging
import cb.tcphijack.ccp_dumb
import cb.tcphijack.connection_monitor
import cb.tcphijack.d2c_nat
import cb.tcphijack.c2d_nat
import cb.util.state
from cb.tcphijack.test.dr2dp_dp_tun import DR2DP_DP_TUN


"""
    Test the ingress_nat, egress_nat, and ability to correctly hijack a TCP connection.
    
    The difficult part is making this all work on a single host (requires root).
    
    The client is of class TClient and covert/decoy servers of class TServer.
    
    The client connects to the decoy destination, and sends it a message.  The hijack
    should connect the client to the covert destination and the covert server should respond.
    
    To make this work on one host there is some trickery.  The tcp hijacker needs IP packets, not
    stream so the client actually connects to an IP address on a TUN device.  The dr2dp_dp_tun translates
    the destination to the decoy_dest address and the src to the tun device address and then sends it on to
    the connection monitor.  Return traffic has the reverse IP fiddling done to it.

    run: sudo -s ; set your pythonpath ; ./tcphijack_test
    
    NOTE: The state.tcphijack.test[decoydest/covertdest] values must be your host's primary IP address, not localhost
    or some other value.  You may need to edit state.py or change the values in the code below.
    
    Expected result: exit code 0, msg "TCP Hijack a success!" printed
    Error result: exit code 1, msg "TCP Hijack Failure"
    
"""

MSG_SIZE = 20000

class TClient(asyncore.dispatcher_with_send):
    def __init__(self, host, port):
        
        asyncore.dispatcher_with_send.__init__(self)
        #super(type(self), self).__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host,port))
        self.state = 'connecting'
        self.msgs_left = 1000
        self.msg = ''
        for i in range(0,MSG_SIZE):
            self.msg += '0'
        self.buff = ''
        
    def handle_connect(self):
        self.send('\xDE\xAD\xBE\xEF for everyone')

    def handle_read(self):
        data = self.recv(MSG_SIZE)
            
        if self.state == 'connecting':
            if data == "I am covert!":
                print "TCP Hijack a success!"                
                self.state = 'streaming'
                self.send(self.msg)
            else:
                print "TCP Hijack Failure"
                sys.exit(1)
                
        elif self.state == 'streaming':
            self.buff += data
            if len(self.buff) < MSG_SIZE:
                return            

            assert(self.buff == self.msg)
            self.buff = ''                

            if self.msgs_left == 0:
                print "All messages transmitted"
                sys.exit(0)
            
            self.send(self.msg)
            
            self.msgs_left -= 1
            print self.msgs_left
        
        
class THandler(asyncore.dispatcher_with_send):
    
    def __init__(self, sock):
        self.buff = ''
        asyncore.dispatcher_with_send.__init__(self, sock)
        
    def handle_read(self):
        data = self.recv(MSG_SIZE)
        if data == '':
            self.close()
            return

        
        if data.startswith('\xDE\xAD\xBE\xEF'):
            self.send(self.msg)
        else:
            self.buff += data
            if len(self.buff) < MSG_SIZE:
                return
                
            self.send(self.buff)
            self.buff = ''
            
class TServer(asyncore.dispatcher):

    def __init__(self, host, port, msg):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        self.msg = msg

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            handler = THandler(sock)
            handler.msg = self.msg
            self.close()

# Grab a local address
LOCAL_IP = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0]

config = dict(decoyproxy=dict(proxyaddr='%s:%d'%(LOCAL_IP,6001)),
              tcp_engine=dict(
                          tun_interface = 'tun0',
                          tun_ip = '10.100.0.1',
                          tun_netmask= '255.255.0.0',
                          tun_src_net = '10.100.128.0/17',
                          tun_max_conn = 100,
                          tun_port = 4445),
              test = dict(tun_interface = 'tun1',
                      tun_ip = '10.99.0.1',
                      decoy_dest = LOCAL_IP,
                      covert_dest = LOCAL_IP,
                      decoy_port = 9999,
                      covert_port = 6001,
                      decoy_tun_dest = '10.99.0.42',
                      tun_netmask = '255.255.255.0'))
                        

COVERT_DEST = config['test']['covert_dest']
COVERT_PORT = config['test']['covert_port']
DECOY_DEST = config['test']['decoy_dest']
DECOY_PORT = config['test']['decoy_port']
DECOY_TUN_DEST = config['test']['decoy_tun_dest']


def test_all():
    state = cb.util.state.State()
    #state.tcphijack.test.decoy_destination = ? 
    dr2dp = DR2DP_DP_TUN(config)
    ingress_nat = cb.tcphijack.c2d_nat.C2DNat(state)
    conn_monitor = cb.tcphijack.connection_monitor.ConnectionMonitor(state, config, ingress_nat)
    dr2dp.register_cm(conn_monitor)
    conn_monitor.register_dr2dp(dr2dp)
    _ = cb.tcphijack.d2c_nat.D2CNat(state, config, conn_monitor, ingress_nat)
    _ = cb.tcphijack.ccp_dumb.CCP_DP(config, conn_monitor)
        
    decoy_server = TServer(DECOY_DEST, DECOY_PORT, "I am a decoy")
    covert_server = TServer(COVERT_DEST, COVERT_PORT, "I am covert!")
    # Dest IP needs to be something on TUN network, it'll 
    # be changed to decoy_server by dr2dp_dp_tun
    client = TClient(DECOY_TUN_DEST, DECOY_PORT)

    asyncore.loop()

if __name__ == '__main__':
    test_all()

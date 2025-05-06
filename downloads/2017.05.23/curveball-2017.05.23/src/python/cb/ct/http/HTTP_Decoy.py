#!/usr/bin/env python2.6
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

import socket
import os
import struct
import logging
import dpkt
import binascii
import time
import sys

from twisted.web import server, resource
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor   
from twisted.web import proxy, http


class ListenForClient(Protocol):
    def __init__(self):
#        self.c = ConnectToServerFactory()       
#        self.c.s = self        
#        reactor.connectTCP('www.nytimes.com', 80, self.c)

        self.c = None
    
    def connectionMade(self):
        print 'Protocol: Client has connected to Decoy.'

    def connectionLost(self, reason):        
        print 'Protocol: Client connection to Decoy has been lost. Reason:', reason.getErrorMessage()
        
    def dataReceived(self, data):
        print 'Protocol: Decoy has received data from client.'
        print data
        self.transport.write('HTTP OK')
#        reactor.connectTCP('www.nytimes.com', 80, self.c)
        
        
class ListenForClientFactory(Factory):

    def startedConnecting(self, connector):
        print 'Factory: Client has started to connect to Decoy.'

    def buildProtocol(self, addr):
        print 'Factory: Client has connected to Decoy.'
        return ListenForClient()

    def clientConnectionLost(self, connector, reason):
        print 'Factory: Client connection to Decoy has failed.  Reason:', reason.getErrorMessage()

    def clientConnectionFailed(self, connector, reason):
        print 'Factory: Client connection to Decoy has been lost. Reason:', reason.getErrorMessage()

class Simple(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        print 'Decoy received request from client'
        print request
        print request.requestHeaders
        print 'Decoy is sending response'
        return "<html>Hello, world!</html>"
    
def main():           
        
    #s = ListenForClientFactory()
    s = server.Site(Simple())
    reactor.listenTCP(8080,s)
    reactor.run()  

if __name__ == '__main__':
    main()

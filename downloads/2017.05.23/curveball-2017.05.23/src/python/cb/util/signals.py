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

class Signals(object):
    """
    Signals is a very primitive callback object.  The idea is that you
    should create a Signal() in your __init__ function, and whenever your object
    wishes to emit a signal it simply calls the emit function with the signal name
    and any arguments that pertain to the signal.
    
    Any entity that wishes to be informed of such signals should have previously
    registered their interested in that signal by calling object.signal.register(signal, callback)
    with their own callback for the signal event.  The callback function should take one argument, which
    is of the same type as the emitter emitted.
    
    Example:
    
    class A(object):
        def __init__(self):
            self.signals = Signals()
        def print(self):
            print "Hello world"
            self.signals.emit('Printed', 'Hello world')
    
    def printed(args):
        print 'The object printed: %s' % args
    
    def main():
        a = A()
        a.signals.register('Printed', printed)
        a.print()
    
    Expected output:
    > Hello world
    > The object printed: Hello world
    """
    
    def __init__(self):
        self.db = {}

    def emit(self, signal, args=None):
        if not signal in self.db:
            return
        for cb in self.db[signal]:
            cb(args)

    def register(self, signal, callback):
        d = self.db.setdefault(signal, [])
        d.append(callback)

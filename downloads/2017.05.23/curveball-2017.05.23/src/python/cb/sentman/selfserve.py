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
A simple wrapper for a KeyCollection on platforms where we don't
run cbsmd for one reason or another.
"""

import binascii
import logging
import os
import tempfile

import cb.util.cblogging

from cb.sentman.keystate import SentmanKey
from cb.sentman.keystate import SentmanKeyCollection
from cb.util.lockfile import SimpleLockFile
from cb.util.platform import PLATFORM

class SentmanSelfServeLockFailed(BaseException):
    """
    Raised if the lockfile cannot be created/acquired
    """
    pass

class SentmanSelfServe(object):
    """
    A simple "self-serve" object to substitutes for cbsmd on systems
    where running cbsmd is awkward.
    
    Stores its state in a file; if the file does not exist, it will
    be created.

    If a key str is provided, then a SentmanKey is created for that key
    (using the defaults for all parameters except the key itself),
    and the keystate is added.  If the key already exists in the
    collection, then this has no effect.

    Instantiating this object allocates a single sentinel (if possible),
    leaving it in self.sentinel.  self.epoch and self.remaining contain
    the time to next epoch and remaining keys (see keystate.py for
    more info)
    """

    def __init__(self, keystate=None, state_fname=None, lock_fname=None,
            generate=False, do_mse=False):

        self.log = logging.getLogger('cb.sentman')

        if not state_fname:
            self.state_fname = self.default_state_fname()
        else:
            self.state_fname = state_fname
        self.log.info('using state file [%s]', self.state_fname)

        if not lock_fname:
            self.lock_fname = self.state_fname + '.lck'
        else:
            self.lock_fname = lock_fname
        self.log.info('using lock file [%s]', self.lock_fname)

        key_collection = SentmanKeyCollection(self.state_fname)

        lockfile = SimpleLockFile(self.lock_fname)

        if not lockfile.acquire():
            err_str = 'cannot acquire lockfile [%s]' % self.lock_fname
            self.log.warn(err_str)
            raise SentmanSelfServeLockFailed(err_str)

        try:
            key_collection.restore_state()

            if keystate:
                key_collection.add_keystate(keystate)

            # Avoid calling key_collection.generate() unless we know
            # we want to generate a sentinel, because otherwise we'll
            # waste a perfectly good sentinel.
            #
            if generate:
                self.sentinel = key_collection.generate(do_mse=do_mse)

            self.remaining = key_collection.remaining()
            self.epoch = key_collection.epoch()
        finally:
            lockfile.release()

    @staticmethod
    def default_state_fname():
        if PLATFORM in ['darwin', 'linux2']:
            home_dir = os.getenv('HOME')
            if not home_dir:
                return None

            state_dir = os.path.join(home_dir, '.curveball')

            if not os.path.isdir(state_dir):
                os.mkdir(state_dir, 0700)

        else:
            state_dir = tempfile.gettempdir()

        return os.path.join(state_dir, 'cbsmd-ss')

    @staticmethod
    def generate(state_fname=None, lock_fname=None, do_mse=False):
        """
        Factory method to create a SentmanSelfServe instance
        and return (sentinel, epoch, remaining)
        """

        selfserve = SentmanSelfServe(None,
                state_fname=state_fname, lock_fname=lock_fname,
                generate=True, do_mse=do_mse)

        if not selfserve.sentinel:
            sentinel = None
        elif do_mse:
            (old_sentinel, dh_exp, dh_pub) = selfserve.sentinel
            sentinel = (binascii.hexlify(old_sentinel), dh_exp, dh_pub)
        else:
            sentinel = binascii.hexlify(selfserve.sentinel)

        return (sentinel, selfserve.epoch, selfserve.remaining)


if __name__ == '__main__':
    def test_main():
        key = 'a' * 256
        kname = 'key-a'

        keystate = SentmanKey(key, kname)
        _dummy = SentmanSelfServe(keystate, 'xxx', 'xxx.lck')

        print SentmanSelfServe.generate(state_fname='xxx',
                lock_fname='xxx.lck', do_mse=True)

        print SentmanSelfServe.generate(state_fname='xxx',
                lock_fname='xxx.lck')
        print SentmanSelfServe.generate(state_fname='xxx',
                lock_fname='xxx.lck')
        print SentmanSelfServe.generate(state_fname='xxx',
                lock_fname='xxx.lck')


        return 0

    exit(test_main())

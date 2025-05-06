#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017 and in
# part by a grant from the United States Department of State.
# The opinions, findings, and conclusions stated herein are those
# of the authors and do not necessarily reflect those of the United
# States Department of State.
#
# Copyright 2014-2016 - Raytheon BBN Technologies Corp.
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
Wrapper for a key.  Encapsulates state needed to create
sentinels in a consistent manner from the key.
"""

import binascii
import calendar
import logging
import os
import re
import sys
import threading
import time

import cb.noc.gen_sentinels
import cb.util.cblogging

from cb.sentman.response import SentmanResponse

DEFAULT_SENTINELS_PER_EPOCH = 1024
DEFAULT_MAX_SENTINELS_PER_EPOCH = 64 * DEFAULT_SENTINELS_PER_EPOCH

# Epoch length is measured in seconds
#
# Don't permit the MIN_EPOCH_LENGTH to go below one minute
#
DEFAULT_EPOCH_LENGTH = 60 * 60
DEFAULT_MAX_EPOCH_LENGTH = 24 * DEFAULT_EPOCH_LENGTH
DEFAULT_MIN_EPOCH_LENGTH = max(DEFAULT_EPOCH_LENGTH // 15, 60)

# Don't permit nonsensical defaults.
#
assert(DEFAULT_SENTINELS_PER_EPOCH > 0)
assert(DEFAULT_EPOCH_LENGTH > 0)
assert(DEFAULT_EPOCH_LENGTH >= DEFAULT_MIN_EPOCH_LENGTH)

KEY_LENGTH_BYTES = 256 # key length, in bytes.
KEY_LENGTH_BITS = (8 * KEY_LENGTH_BYTES) # key length, in bits.

class SentmanKey(object):
    """
    Implements the state associated with a Sentman key
    """

    def __init__(self, key, kname,
            sentinels_per_epoch=DEFAULT_SENTINELS_PER_EPOCH,
            epoch_length=DEFAULT_EPOCH_LENGTH,
            epoch_start=None,
            remaining_sentinels=DEFAULT_SENTINELS_PER_EPOCH):
        """
        key - the binary string of digits (not hex) that represent the
        full key

        kname - the name of the key

        sentinels_per_epoch - the number of sentinels that can be generated
        for this key per epoch.  Setting this to zero creates a "dead key"
        that cannot generate any sentinels, but serves as a tombstone
        in a SentmanKeyCollection (see below).

        epoch_length - the epoch length, in seconds

        epoch_start - the start of the current epoch, relative to the start
        of the UNIX epoch.  If None, then it is assume that the begining
        of the current hour was the beginning of this or a former epoch,
        and the epoch is incremented forward until the current time is
        reached.  For example, if the epoch length is 10 minutes, and the
        current time is 10:34, then the start of the current epoch will be
        assume to be 10:30.  Note that this heuristic makes little sense
        if the epoch length does not evenly divide an hour, or in hours
        containing leap seconds (and possibly DST shifts).

        remaining_sentinels - the number of sentinels remaining
        in the current epoch
        """

        self.log = logging.getLogger('cb.sentman')
        self.log.debug('created new SentmanKey')

        # Check that the key is properly formed.
        #
        if type(key) != str:
            err_str = 'key must be a str (not %s)' % str(type(key))
            self.log.warn(err_str)
            raise TypeError(err_str)

        if len(key) != KEY_LENGTH_BYTES:
            err_str = 'key must be %d bytes long (not %d)' % (
                    KEY_LENGTH_BYTES, len(key))
            self.log.warn(err_str)
            raise ValueError(err_str)

        # Check that the kname is properly formed.
        #
        if type(kname) != str:
            err_str = 'kname must be a str (not %s)' % str(type(kname))
            self.log.warn(err_str)
            raise TypeError(err_str)

        # TODO: there are additional constraints for knames,
        # but we don't enforce them here.

        self.key = key
        self.kname = kname

        # Check that sentinels_per_epoch, epoch_length are sane
        #
        # The current definition of "sane" is arbitrary and may not
        # stand up to real use.  These numbers are swags.
        #
        max_epoch_length = DEFAULT_MAX_EPOCH_LENGTH
        min_epoch_length = DEFAULT_MIN_EPOCH_LENGTH
        max_sentinels_per_epoch = DEFAULT_MAX_SENTINELS_PER_EPOCH

        if (type(sentinels_per_epoch) != int) or (sentinels_per_epoch < 0):
            raise TypeError('sentinels_per_epoch must be a positive int')
        if sentinels_per_epoch > max_sentinels_per_epoch:
            raise ValueError('sentinels_per_epoch must be <= %d' %
                    max_sentinels_per_epoch)

        if (type(epoch_length) != int) or (epoch_length < 0):
            raise TypeError('epoch_length must be a positive int')
        if epoch_length > max_epoch_length:
            raise ValueError('epoch_length must be <= %d' %
                    max_sentinels_per_epoch)
        if epoch_length < min_epoch_length:
            raise ValueError('sentinels_per_epoch must be >= %d' %
                    min_epoch_length)

        self.sentinels_per_epoch = sentinels_per_epoch
        self.epoch_length = epoch_length
        self.epoch_start = epoch_start

        # If no epoch_start is given, round down to the most recent hour,
        # and then increment until we find a good starting point.
        #
        # The first step is accomplished by getting the time in tuple
        # representation (see time.gmtime()), making a list from the tuple,
        # zeroing the minute and second fields, reconstructing the tuple, and
        # passing it to calendar.timegm().  It seems like there would be an
        # easier way.
        #
        if self.epoch_start == None:
            now = time.time()
            this_hour = list(time.gmtime(now))
            this_hour[4] = 0
            this_hour[5] = 0
            self.epoch_start = calendar.timegm(tuple(this_hour))

            # Now bump up the current epoch until it includes the current
            # time:
            #
            while (self.epoch_start + self.epoch_length) < now:
                self.epoch_start += self.epoch_length

        self.next_epoch_start = self.epoch_start + self.epoch_length

        if remaining_sentinels > self.sentinels_per_epoch:
            remaining_sentinels = self.sentinels_per_epoch

        self.remaining_sentinels = remaining_sentinels

        self._update()

    def __str__(self):

        self._update()

        buf = ''
        buf += 'kname %s ' % self.kname
        buf += 'key %s ' % binascii.hexlify(self.key)
        buf += 'remaining %d ' % self.remaining_sentinels
        buf += 'sentinels_per_epoch %d ' % self.sentinels_per_epoch
        buf += 'epoch_length %d ' % self.epoch_length
        buf += 'next_epoch_start %d ' % self.next_epoch_start

        return buf

    @staticmethod
    def from_str(text):
        """
        Given a text description of a SentmanKey instance (as created by
        __str__), create a new instance with the same behavior.

        Note that the fields might not be exactly identical (for example,
        next_epoch_start is rolled forward to the next epoch, which could
        be different than the text.  (If the next_epoch_start in the text
        is bogus, then the result here could also be bogus)
        """

        text = text.strip()

        pattern = ''
        pattern += 'kname ([a-zA-Z0-9_.-]+) '
        pattern += 'key ([0-9a-fA-F]{512}) '
        pattern += 'remaining ([0-9]+) '
        pattern += 'sentinels_per_epoch ([0-9]+) '
        pattern += 'epoch_length ([0-9]+) '
        pattern += 'next_epoch_start ([0-9]+)'
        pattern += '$'

        match = re.match(pattern, text)
        if not match:
            raise ValueError('old cbsmd-ss? ' +
                    'text does not match required pattern [%s]' % text)

        kname = match.group(1)
        key = binascii.unhexlify(match.group(2))
        remaining = int(match.group(3))
        sentinels_per_epoch = int(match.group(4))
        epoch_length = int(match.group(5))
        next_epoch_start = int(match.group(6))

        instance = SentmanKey(key, kname, sentinels_per_epoch, epoch_length,
                next_epoch_start - epoch_length, remaining)

        return instance

    def _update(self):
        """
        self.next_epoch_start and self.remaining_sentinels are is intended to
        indicate the start of the next epoch, and how many sentinels remain in
        the current epoch, but these values are only accurate if the they are
        rolled forward whenever necessary.  This routine rolls the
        next_epoch_start forward until it takes place in the future.  We also
        need to reset self.remaining_sentinels at the same time, to reflect that
        the remaining sentinels gets reset whenever
        """

        now = time.time()
        while now > self.next_epoch_start:
            self.next_epoch_start += self.epoch_length
            self.remaining_sentinels = self.sentinels_per_epoch

        return

    def remaining(self):
        """
        return the number of remaining sentinels that can be generated
        in the current epoch
        """

        self._update()
        return self.remaining_sentinels

    def epoch(self):
        """
        Return the number of seconds until the end of the current epoch
        """

        self._update()
        return self.next_epoch_start - time.time() 

    def generate(self, do_mse=False):
        """
        Generate a new sentinel and return it, or None if a sentinel
        cannot be generated.

        When a sentinel is generated, the remaining_sentinels is
        decremented

        If do_mse is not False, then create an MSE sentinel and sentinel
        label and return a tuple containing the sentinel (as a binary
        string) and the Diffie-Hellman exponent.  Otherwise, create and
        return a TLS-style sentinel.
        """

        self._update()

        # This could be a disabled key.
        #
        if self.sentinels_per_epoch <= 0:
            return None

        # If the epoch has rolled over, roll next_epoch_start forward until
        # it is once again in the future, and refill the remaining.
        #
        # This isn't the most elegant way to roll forward, but it's the
        # simplest.
        #

        if self.remaining_sentinels <= 0:
            return None

        self.remaining_sentinels -= 1

        if do_mse:
            (hex_sentinel, dh_exp, dh_pub) = \
                    cb.noc.gen_sentinels.create_mse_sentinel(
                            binascii.hexlify(self.key),
                            self.remaining_sentinels)
            sentinel = binascii.unhexlify(hex_sentinel)

            return (sentinel, dh_exp, dh_pub)
        else:
            hex_sentinel = cb.noc.gen_sentinels.create_sentinel(
                    binascii.hexlify(self.key), self.remaining_sentinels)
            sentinel = binascii.unhexlify(hex_sentinel)

            return sentinel

class SentmanKeyCollection(object):
    """
    Collection of a set of SentmanKey instances
    """

    def __init__(self, statefile=None, reset=False):
        """
        statefile - where the state describing the current set of keys
        is stored

        reset - if not False, then ignore the current contents of statefile
        (if any) and start with an empty statefile
        """

        self.log = logging.getLogger('cb.sentman')
        self.log.debug('created new SentmanKeyCollection')

        self.lock = threading.RLock()

        if statefile:
            if type(statefile) != str:
                err_str = 'statefile must be a str (not %s)' % type(statefile)
                self.log.warn(err_str)
                raise TypeError(err_str)

            if not os.path.basename(statefile):
                err_str = 'statefile must not be a directory'
                self.log.warn(err_str)
                raise ValueError(err_str)

            dirname = os.path.dirname(statefile) or '.'
            if not os.path.isdir(dirname):
                err_str = 'statefile directory must exist'
                self.log.warn(err_str)
                raise ValueError(err_str)

        # A map from keys to SentmanKey instances.  This is used to ensure
        # that no key appears more than once in a collection.
        #
        self.key2state = {}

        self.statefile = statefile
        self.error_str = ''

        if self.statefile:
            if os.path.exists(self.statefile):
                if reset:
                    self.log.info('clearing state from [%s]' % self.statefile)
                    os.remove(self.statefile)
                else:
                    self.log.info('restoring state from [%s]' % self.statefile)
                    self.restore_state()
            else:
                self.error_str = 'Key statefile does not exist'
        else:
            self.error_str = 'No key statefile specified'

    def __str__(self):

        with self.lock:
            buf = 'SentmanKeyCollection '
            buf += 'statefile [%s] ' % self.statefile

            buf += 'keys '
            if self.key2state:
                buf += '[\n'
                for key in self.key2state:
                    buf += '    %s,\n' % str(self.key2state[key])
                buf += ']'
            else:
                buf += '[ ]'

            return buf

    def add_keystate(self, keystate):
        """
        Add the given keystate to the collection, if the key for the
        keystate is not already associated with any item in the collection

        Returns True if the key is added, False otherwise.
        """

        if not isinstance(keystate, SentmanKey):
            err_str = 'keystate not SentmanKey (is %s)' % str(type(keystate))
            self.log.error(err_str)
            raise TypeError(err_str)

        with self.lock:
            if keystate.key in self.key2state:
                # Don't add the same key again.
                # self.log.warn('attempted to add a key twice')
                return False
            else:
                self.key2state[keystate.key] = keystate
                self.persist_state()
                return True

    def drop_keystate(self, keystate):
        """
        Remove the keystate from the current collection, if present.

        Returns True if the key is found and removed, False otherwise.
        """

        if not isinstance(keystate, SentmanKey):
            err_str = 'keystate not SentmanKey (is %s)' % str(type(keystate))
            self.log.error(err_str)
            raise TypeError(err_str)

        with self.lock:
            if keystate.key in self.key2state:
                del self.key2state[keystate.key]
                self.persist_state()
                return True
            else:
                return False

    def generate(self, do_mse=False):
        """
        Generate and return a new sentinel from a keystate in the collection,
        or return None if the collection is empty or all of the keys are
        exhausted in the current epoch.

        If do_mse is not False, then create an MSE sentinel and sentinel
        label and return a tuple containing the sentinel (as a binary
        string) and the Diffie-Hellman exponent.  Otherwise, create and
        return a TLS-style sentinel.

        If there are no keys at all, return a ValueError to differentiate this
        from running out of sentinels.
        """

        sentinel = None

        with self.lock:

            if len(self.key2state) == 0:
                if self.error_str:
                    raise ValueError(self.error_str)
                else:
                    raise ValueError('No active keys found')

            for key in self.key2state:
                keystate = self.key2state[key]
                if do_mse:
                    (sentinel, dh_exp, dh_pub) = keystate.generate(do_mse=True)
                else:
                    sentinel = keystate.generate()

                if sentinel:
                    break

            # If we generated a sentinel, update the persistent state.
            #
            if sentinel:
                self.persist_state()

        if do_mse:
            return (sentinel, dh_exp, dh_pub)
        else:
            return sentinel

    def remaining(self):
        """
        Return the total number of sentinels remaining in the
        current epoch.
        """

        with self.lock:
            if not self.key2state:
                return SentmanResponse.UNKNOWN_REMAINING
            else:
                total = 0

                for key in self.key2state:
                    keystate = self.key2state[key]
                    total += keystate.remaining()

                return total

    def epoch(self):
        """
        Return the number of seconds until more keys are available
        because of an epoch change.

        Returns None if there are no keystates in the collection
        """

        epoch = SentmanResponse.UNKNOWN_EPOCH

        with self.lock:
            for key in self.key2state:
                keystate = self.key2state[key]
                epoch_candidate = keystate.epoch()
                if epoch > epoch_candidate:
                    epoch = epoch_candidate

        return epoch

    def persist_state(self):
        """
        Store the current state of the collection in a persistent
        form that can be loaded again later, if needed.
        """

        if not self.statefile:
            return

        with self.lock:
            try:
                tmp_fname = '%s.tmp' % self.statefile

                # WARNING: only portable to POSIX
                #
                fd = os.open(tmp_fname,
                        os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0600)
                fout = os.fdopen(fd, 'w+')
                for key in self.key2state:
                    text = str(self.key2state[key])
                    fout.write(text + '\n')
                fout.close()
            except BaseException, exc:
                self.log.warn('failed to record state to %s: %s', tmp_fname, str(exc))
                raise exc
                return

            # Windows does not permit renames over existing files
            #
            if sys.platform == 'win32':
                if os.path.exists(self.statefile):
                    os.remove(self.statefile)

            try:
                os.rename(tmp_fname, self.statefile)
            except BaseException, exc:
                self.log.warn('failed to store state(rename %s to %s): %s',
                        tmp_fname, self.statefile, str(exc))
                raise exc

    def restore_state(self):
        """
        Restore the state in the given statefile
        """

        if not self.statefile:
            return

        with self.lock:
            try:
                fin = open(self.statefile, 'r')
                lines = fin.readlines()
                fin.close()
            except IOError, exc:
                self.log.warn('%s' % str(exc))
                return
            except BaseException, exc:
                self.log.error('could not read statefile [%s]' % str(exc))
                raise exc
                return

            for line in lines:
                self.add_keystate(SentmanKey.from_str(line))

def load_key(path):
    """
    Load the first key in the given key file, and return it.

    THIS ROUTINE IS EXPECTED TO CHANGE to track changes in the
    format of the key file, but the way these files are formatted
    right now is the following: each line contains an integer (the
    key number) followed by whitespace, and then 512 hex digits
    representing the key.
    """

    log = logging.getLogger('cb.sentman')

    try:
        fin = open(path, 'r')
        lines = fin.readlines()
        fin.close()
    except BaseException, exc:
        log.warn('cannot open keyfile [%s]: %s', path, str(exc))
        return None

    for line in lines:
        fields = line.split()
        if len(fields) > 1:
            match = re.match('([0-9a-fA-F]+)$', fields[1])
            if match and len(match.group(1)) == 512:
                hex_key = match.group(1)
                log.info('returning key [%s]', hex_key)
                key = binascii.unhexlify(hex_key)
                return key

    log.warn('no key found in [%s]', path)
    return None


if __name__ == '__main__':

    def test_exhaust():
        """
        Simple unit test to check that the number of sentinels produced is
        correct.
        """

        collection = SentmanKeyCollection()

        # Make some bogus keys

        fake_key1 = chr(0x11) * 256
        fake_key2 = chr(0x22) * 256
        fake_key3 = chr(0x33) * 256

        # These need to be checked by eyeball.
        #
        key1 = SentmanKey(fake_key1, 'fake-key1', epoch_length=600,
                sentinels_per_epoch=2)
        key2 = SentmanKey(fake_key2, 'fake-key2', epoch_length=600,
                sentinels_per_epoch=2)
        key3 = SentmanKey(fake_key3, 'fake-key3', epoch_length=600,
                sentinels_per_epoch=2)

        collection.add_keystate(key1)
        collection.add_keystate(key2)
        collection.add_keystate(key3)

        # We added three keys, each with two sentinels per epoch, so we should
        # be able to allocate six sentinels (unless we're unfortunate and this
        # program straddles two epochs, in which case we might get as many as
        # twelve)

        for index in range(0, 6):
            sentinel = collection.generate()
            if not sentinel:
                print 'ERROR: expected to allocate sentinel %d' % index
                return False

        # Now, we should be exhausted

        sentinel = collection.generate()
        if sentinel:
            print 'ERROR: expected to NOT allocate another sentinel'
            return False

        return True

    def test_persist():
        """
        Tests persistance and restoring
        """

        collection = SentmanKeyCollection(statefile='TEST-TEMP', reset=True)

        # Make some bogus keys

        fake_key1 = chr(0x11) * KEY_LENGTH_BYTES
        fake_key2 = chr(0x22) * KEY_LENGTH_BYTES
        fake_key3 = chr(0x33) * KEY_LENGTH_BYTES

        key1 = SentmanKey(fake_key1, 'key-a', epoch_length=600,
                sentinels_per_epoch=2)
        key2 = SentmanKey(fake_key2, 'key-b', epoch_length=600,
                sentinels_per_epoch=2)
        key3 = SentmanKey(fake_key3, 'key-c', epoch_length=600,
                sentinels_per_epoch=2)

        collection.add_keystate(key1)
        collection.add_keystate(key2)
        collection.add_keystate(key3)

        # We added three keys, each with two sentinels per epoch, so we should
        # be able to allocate six sentinels (unless we're unfortunate and this
        # program straddles two epochs, in which case we might get as many as
        # twelve).  We just try to allocate three.

        for index in range(0, 3):
            sentinel = collection.generate()
            if not sentinel:
                print 'ERROR: expected to allocate sentinel %d' % index
                return False

        # Now make a new collection with the same statefile.  It should be
        # functionally identical to collection.  Try allocating three more
        # sentinel, and then see if we're exhausted.

        collection2 = SentmanKeyCollection(statefile='TEST-TEMP')

        for index in range(3, 6):
            sentinel = collection2.generate()
            if not sentinel:
                print 'ERROR: expected to allocate sentinel %d' % index
                return False

        # Now, we should be exhausted

        sentinel = collection2.generate()
        if sentinel:
            print 'ERROR: expected to NOT allocate sentinel %d' % index + 1
            return False

        return True

    def test_mse():

        fake_key1 = chr(0x11) * KEY_LENGTH_BYTES
        key1 = SentmanKey(fake_key1, 'fake-key1', epoch_length=600,
                sentinels_per_epoch=2)

        # needs to be eyeballed
        print key1.generate(do_mse=True)

    def test_main():
        """
        Test main - incomplete
        """

        test_mse()

        errors = 0

        if not test_exhaust():
            errors = 1

        if not test_persist():
            errors = 1

        return errors

    exit(test_main())

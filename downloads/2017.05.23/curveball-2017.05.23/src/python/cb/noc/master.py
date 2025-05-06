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
Classes for dealing with the master file, which contains the status,
kname, and key string for each key
"""

import os
import re
import sys

class CbkmMasterFileRecord(object):
    """
    A record from the CbkmMasterFile
    """

    BITS_PER_KEY = 2048
    BYTES_PER_KEY = BITS_PER_KEY / 8
    HEX_PER_KEY = BITS_PER_KEY / 4

    ACTIVE = 'A'
    REVOKED = 'R'

    VALID_STATUS_LIST = [ACTIVE, REVOKED]

    def __init__(self, status, kname, key):

        # check that the key is OK.  If a key is not provided,
        # create one
        #
        # TODO: we assume that os.urandom is available, which is OK
        # as long as we only have a small number of platforms we
        # need to support for the NOC (Linux) but not universally.
        #
        # Note that verification is done last, after the members
        # have been initialized.

        if not key:
            key = self.gen_key()

        self.status = status
        self.kname = kname
        self.key = key

        self.verify()

    @staticmethod
    def verify_status(status):
        """
        Raise an exception if the given status is invalid
        """

        if not type(status) == str:
            raise TypeError('status must be a str (not %s)' %
                    str(type(status)))
        elif not status in CbkmMasterFileRecord.VALID_STATUS_LIST:
            raise ValueError('Illegal status [%s]' % status)

    @staticmethod
    def verify_kname(kname):
        """
        Raise an exception if the given kname is invalid
        """

        if not type(kname) == str:
            raise TypeError('kname must be a str (not %s)' % str(type(kname)))
        elif len(kname) == 0:
            raise ValueError('kname must not be empty')
        elif not re.match('^[0-9a-zA-Z_.@-]*$', kname):
            raise ValueError('Illegal char in kname [%s]' % kname)

    @staticmethod
    def verify_key(key):
        """
        Raise an exception if the given key is invalid
        """

        if not type(key) == str:
            raise TypeError('Key must be a str (not %s)' %
                    str(type(key)))
        elif len(key) != CbkmMasterFileRecord.HEX_PER_KEY:
            raise ValueError('Key must be a %d-digit hex string' %  
                    CbkmMasterFileRecord.HEX_PER_KEY)
        elif not re.match('^[0-9a-fA-F]{%d}$' %
                CbkmMasterFileRecord.HEX_PER_KEY, key):
            raise ValueError('Key must be a %d-digit hex string' %  
                    CbkmMasterFileRecord.HEX_PER_KEY)

    def verify(self):
        """
        Verify that this record satisfies all internal constraints;
        raise an informative exception if not.
        """

        self.verify_kname(self.status)
        self.verify_kname(self.kname)
        self.verify_kname(self.key)

    @staticmethod
    def gen_key():
        """
        Create and return a new, random key.

        We count on probability to ensure that this is very likely
        to be a globally unique and unpredictable key.
        """

        rand_bytes = os.urandom(CbkmMasterFileRecord.BYTES_PER_KEY)
        key = rand_bytes.encode('hex_codec')

        return key

    def __str__(self):
        """
        Represent the record as a string
        """

        return '%s %s %s' % (self.status, self.kname, self.key)


class CbkmMasterFile(object):
    """
    The MasterFile representing the state of all knames and keys
    """

    def __init__(self, path=None):

        self.path = path

        self.kname2record = dict()
        self.key2record = dict()
        self.records = list()

        # self.dirty is True whenever there have been changes to
        # the master file that have not been pushed to file.
        #
        self.dirty = False

        if self.path:
            try:
                lines = open(self.path).readlines()
            except IOError, exc:
                print 'ERROR: cannot open master file [%s]: %s' % (
                        self.path, str(exc))
                raise exc

            data_lines = [re.sub('#.*$', '', line).strip() for line in lines]

            data_lines = [line for line in data_lines if line]

            try:
                self.records = [CbkmMasterFileRecord(*line.split())
                        for line in data_lines]
            except BaseException, exc:
                print 'Warning: master key file - invalid format:'
                print '    [%s]' % str(exc)
                raise exc

            for record in self.records:
                if record.kname in self.kname2record:
                    raise KeyError('kname [%s] already present' % record.kname)
                else:
                    self.kname2record[record.kname] = record

                if record.key in self.key2record:
                    raise KeyError('key [%s] already present' % record.key)
                else:
                    self.key2record[record.key] = record

    @staticmethod
    def default_master_fname():
        """
        Return the default location of the master file.

        Note that the path to the master file depends on the location
        of the script that invokes this command: if Curveball is installed
        in /opt/curveball, it will look in subdirectories of /opt/curveball,
        but in your development area it will look there.
        """

        exedir = os.path.abspath(os.path.dirname(sys.argv[0]) or '.')

        return os.path.normpath(
                os.path.join(exedir, '..', 'auth', 'keys', 'master.km'))


    def to_file(self, path=None):
        """
        Write the current state to the file at the given path.

        If path is not provided or None, then use the same path
        that the master file was read from.  If the master file
        was not read from a file, then raise ValueError.
        """

        if path == None:
            path = self.path

            # If we're writing in place, and the data is clean,
            # we don't need to do anything
            #
            if not self.dirty:
                return

        if path == None:
            raise ValueError('No path provided')

        # TODO error checking
        fout = open(path, 'w+')

        for record in self.records:
            print >> fout, str(record)

        fout.close()

    def to_key_file(self, path):
        """
        Dump the records for active knames to a key file
        at the given path.
        """

        try:
            fout = open(path, 'w+')
        except BaseException, exc:
            print 'ERROR saving key file: %s' % str(exc)
            return

        for kname in sorted(self.kname2record.keys()):
            record = self.kname2record[kname]
            if record.status == CbkmMasterFileRecord.ACTIVE:
                fout.write('%s %s\n' % (record.kname, record.key))

        fout.close()

    def add_record(self, record):
        """
        Add a new record to the master file.
        """

        if not isinstance(record, CbkmMasterFileRecord):
            raise TypeError('must be a CbkmMasterFileRecord')

        key = record.key
        kname = record.kname
        status = record.status

        if kname in self.kname2record:
            raise ValueError('kname [%s] already present' % str(kname))

        if key in self.key2record:
            raise ValueError('key [%s] already present' % str(key))

        # Creating a clone forces revalidation
        #
        new_record = CbkmMasterFileRecord(status, kname, key)

        self.records.append(new_record)
        self.dirty = True

        self.kname2record[new_record.kname] = new_record
        self.key2record[new_record.key] = new_record

    def revoke_kname(self, kname):
        """
        Revoke the given kname.

        Has no effect if the kname is already revoked.

        Raises a KeyError if the kname is not present
        """

        if kname in self.kname2record:
            record = self.kname2record[kname]
            if record.status != CbkmMasterFileRecord.REVOKED:
                record.status = CbkmMasterFileRecord.REVOKED
                self.dirty = True
        else:
            raise KeyError('Cannot revoke [%s]: no such kname' % kname)

    def rekey_kname(self, kname):
        """
        Rekey the given kname with a fresh key, and make it active

        Raises a KeyError if the kname is not present
        """

        if kname in self.kname2record:
            record = self.kname2record[kname]
            record.key = CbkmMasterFileRecord.gen_key()
            if record.status != CbkmMasterFileRecord.ACTIVE:
                record.status = CbkmMasterFileRecord.ACTIVE
            self.dirty = True
        else:
            raise KeyError('Cannot revoke [%s]: no such kname' % kname)

    def unrevoke_kname(self, kname):
        """
        "Unrevoke" the given kname, without rekeying.

        NOTE: this is a dangerous operation, provided only for test.
        If a key is revoked, presumably it is because it has been
        compromised or shown to be weak, and it should be discarded,
        not activated again.

        Has no effect if the kname is already active.

        Raises a KeyError if the kname is not present
        """

        if kname in self.kname2record:
            record = self.kname2record[kname]
            if record.status != CbkmMasterFileRecord.ACTIVE:
                record.status = CbkmMasterFileRecord.ACTIVE
                self.dirty = True
        else:
            raise KeyError('Cannot enable [%s]: no such kname' % kname)

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

# Sentinel Header Classes

import sys
import datetime
import hashlib

sys.path.append('../../../python')
import cb.noc.file
import gen_sentinels

# Defined header values 
SENTINEL_HEADER_VERSION = 1
## Header Types
SENTINEL_BF_FILE = 0
SENTINEL_FILE = 1
SENTINEL_BF_DATA = 2
SENTINEL_DATA = 3
## Hash Types
SFH = 1

class SentinelBFHeader(object):
    '''
    Object for storing metadata about the sentinel bloom filter stored in the file containing this and the SentinelBFData object
    '''
    version = SENTINEL_HEADER_VERSION
    hdr_type = SENTINEL_BF_FILE
    hash_type = SFH
    error_rate = 1e-6

    def __init__(self):
        '''
        Create an empty sentinel bloom filter file header
        '''
        # time the BF becomes valid
        self.epoch_begin = None
        # how long the BF is valid
        self.nhours = None
        self.sentinel_length = None
        # number of sentinels loaded in this BF
        self.totalnum = None
        # size (in bits) of the hash values used to index into the BF.
        # BF is 2**(hash_size)
        self.hash_size = None
        # error rate
        self.error_rate = None
        # list of 32-bit salt values used to index into the BF
        self.salts = list()


    
    def fill(self, begin, nhours, number, e_rate, hash_sz, salts):
        '''
        Fill a SentinelBFHeader object
        '''

        # Check for goodness
        if type(begin) != datetime.datetime:
            raise TypeError('illegal epoch_begin type (%s)' %
                            ((str(type(begin))),))
        
        if type(nhours) != int:
            raise TypeError('illegal nhours type (%s)' %
                            ((str(type(nhours))),))
        
        if type(number) != int:
            raise TypeError('illegal num_sentinels type (%s)' %
                            ((str(type(number))),))
        
        if type(e_rate) != float:
            raise TypeError('illegal error_rate type (%s)' %
                            ((str(type(e_rate))),))
       
        if type(hash_sz) != int:
            raise TypeError('illegal hash_size type (%s)' %
                            ((str(type(hash_sz))),))

        if type(salts) != list:
            raise TypeError('illegal salts type (%s)' %
                            ((str(type(salts))),))

        
        self.epoch_begin = begin
        self.nhours = nhours
        self.totalnum = number
        self.error_rate = e_rate
        self.hash_size = hash_sz
        self.salts = salts

    def __str__(self):
        """
        Create a human readable string describing the sentinel BF header

        The string will not contain a representation of the sentinel BF data
        """

        text = 'SentinelBFHeader'
        text += ' ver: %u,' % self.version
        text += ' type: %u,' % self.hdr_type
        text += ' hash_type: %u,' % self.hash_type 
        if self.epoch_begin != None:
            text += ' begin @ %sZ,' % gen_sentinels.create_date_hmac_str(self.epoch_begin)
        else:
            text += ' begin: %s,' % self.epoch_begin
        if self.nhours != None:
            text += ' nhrs: %u,' % self.nhours
        else:
            text += ' nhrs: %s,' % self.nhours
        if self.error_rate != None:
            text += ' error_rate: %G' % self.error_rate
        else:
            text += ' error_rate: %s' % self.error_rate
        if self.hash_size != None:
            text += ' hash_size: %u,' % self.hash_size
        else:
            text += ' hash_size: %s,' % self.hash_size
        text += ' num salts: %u,' % len(self.salts)
        text += ' salts: %s' % self.salts
        
        return text

    def info(self):
        '''
        pretty print Sentinel BF Header object
        '''
        text = ' (v%u) Sentinel BF File \n' %  self.version
        text += ' Begins @ %s' % cb.noc.file.date_label_str(self.epoch_begin)
        text += ' for %u hours \n' % self.nhours
        text += ' Contains'
        text += ' %u sentinels \n' % self.totalnum
        text += ' hash_size: %u,' % self.hash_size
        text += ' number of salts %u,' % len(self.salts)
        text += ' salts %s \n' % self.salts
        print text


class SentinelFileHeader(object):
    '''
    Object for storing metadata about the sentinels stored in the file containing this and the SentinelFileData object
    '''
    # set class variables to defaults
    version  = SENTINEL_HEADER_VERSION
    hdr_type = SENTINEL_FILE
    def __init__(self):
        '''
        create an empty sentinel file header
        '''
        # time the sentinels become valid 
        self.epoch_begin = None
        # number of hours the sentinels are valid
        self.nhours = None
        # the length of each sentinel
        self.sentinel_length = None
        # the number of sentinels per key
        self.num_sentinels = None
        # the number of keys used
        self.num_keys = None
        # the total number of sentinels in the file
        self.totalnum = None
        # name of the file containing the keys used to generate the sentinels
        self.key_file_name = None
        # SHA256 hash of file identifed as key_file_name
        self.key_file_hash = None
	
	
    def fill(self, begin, nhours, s_length, number, numkeys, kf_name, kf_hash):
        '''
        fill a SentinelFileHeader objext
        '''
        # Check for goodness
        if type(begin) != datetime.datetime:
            raise TypeError('illegal epoch_begin type (%s)' %
                            ((str(type(begin))),))
        
        if type(nhours) != int:
            raise TypeError('illegal nhours type (%s)' %
                            ((str(type(nhours))),))
        
        if type(s_length) != int:
            raise TypeError('illegal sentinel_length type (%s)' %
                            ((str(type(s_length))),))
        
        if type(number) != int:
            raise TypeError('illegal num_sentinels type (%s)' %
                            ((str(type(number))),))
        
        if type(numkeys) != int:
            raise TypeError('illegal num_keys type (%s)' %
                            ((str(type(numkeys))),))
        
        if type(kf_name) != str:
            raise TypeError('illegal key_file_name type (%s)' %
                            ((str(type(kf_name))),))
        
        if type(kf_hash) != str:
            raise TypeError('illegal key_file_hash type (%s)' %
                            ((str(type(kf_hash))),))
        
        self.epoch_begin = begin
        self.nhours = nhours
        self.sentinel_length = s_length
        self.num_sentinels = number
        self.num_keys = numkeys
        self.key_file_name = kf_name
        self.key_file_hash = kf_hash
        self.totalnum = number*numkeys

    def __str__(self):
        """
        Create a human readable string describing the sentinel file header

        The string will not contain a representation of the sentinel file data
        """
        
        if type(self.hdr_type) != int:
            raise TypeError('illegal hdr_type  (%s), should be (%s)' %
                            ((str(type(self.hdr_type))),
                              (str(type(SENTINEL_FILE))),))
        if self.hdr_type != SENTINEL_FILE:
            raise ValueError('illegal hdf_type value (%u)' % (self.hdr_type,))

        text = '{SentinelFileHeader'
        text += ' ver: %u,' % self.version
        text += ' type: %u,' % self.hdr_type
        if self.epoch_begin != None:
            text += ' begin @ %sZ,' % gen_sentinels.create_date_hmac_str(self.epoch_begin)
        
        text += ' nhrs: %u,' % self.nhours
        text += ' length: %u bits,' % (self.sentinel_length*4)
        text += ' num_sentinels per key: %u,' % self.num_sentinels
        text += ' num_keys: %u,' % self.num_keys
        text += ' total_num_sentinels: %u,' % self.totalnum
        text += ' keyfile: %s,' % self.key_file_name
        text += ' SHA256(keyfile):%s}' % self.key_file_hash

        return text

    def info(self):
        '''
        pretty print Sentinel File Header object
        '''
        text = ' (v%u) Sentinel File \n' %  self.version
        text += ' Begins @ %s' % cb.noc.file.date_label_str(self.epoch_begin)
        text += ' for %u hours \n' % self.nhours
        text += ' Contains'
        text += ' %u' % self.totalnum
        text += ' %u-bit hexadecimal-encoded sentinels' % (self.sentinel_length*4)
        text += ' (%s sentinels per key)\n' % self.num_sentinels
        #text += ' num_keys %u' % self.num_keys
        text += ' Generated from %s' % self.key_file_name
        text += ' (SHA-256 hash): \n %s \n' % self.key_file_hash
        print text

        
class SentinelFileData(object):
    '''
    Object containing the sentinel data
    '''
    version = SENTINEL_HEADER_VERSION
    hdr_type = SENTINEL_DATA
    
    def __init__(self, sentinel=None):
        '''
        init with None or list of sentinel strings \n terminated 
        '''
        # Check for goodness
        if type(sentinel) != list:
            raise TypeError('illegal data type for sentinels (%s)' %
                            ((str(type(sentinel))),))

        self.sentinels = sentinel
        
    def add(self, sentinel):
        """
        adds sentinels to object
        
        """
        # Check for goodness
        if type(sentinel) != list:
            raise TypeError('illegal data type (%s)' %
                            ((str(type(sentinel))),))
	if self.sentinels == None:
		self.sentinels = list()
	self.sentinels.append(sentinel)

    def get_sentinels(self):
        '''
        return stored sentinels as a list or 
        empty list if never set
        '''
        if self.sentinels == None:
            return list()
        else:
            return self.sentinels
    

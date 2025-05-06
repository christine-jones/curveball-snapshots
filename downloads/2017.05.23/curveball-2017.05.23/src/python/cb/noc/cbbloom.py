#!/usr/bin/env python
#
# Copyright (c) <2011> <Jay Baird and Bob Ippolito>
# 
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# cbbloom based on pybloom v1.1 in
# https://github.com/jaybaird/python-bloomfilter
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies

"""This module implements a bloom filter probabilistic data structure 

Requires the bitarray library: http://pypi.python.org/pypi/bitarray/

    >>> from cbbloom import CB_BloomFilter
    >>> f = CB_BloomFilter(capacity=10000, error_rate=0.001)
    >>> for i in xrange(0, f.capacity):
    ...     _ = f.add(i)
    ...
    >>> 0 in f
    True
    >>> f.capacity in f
    False
    >>> len(f) <= f.capacity
    True
    >>> abs((len(f) / float(f.capacity)) - 1.0) <= f.error_rate
    True

"""

import hashlib
import math
import random
import struct

import cb.util.smoosh1_hash

try:
    import bitarray
except ImportError:
    raise ImportError('cbbloom requires bitarray >= 0.3.4')

__version__ = '1.1.a'
__author__  = """
        Jay Baird <jay@mochimedia.com>,
        Bob Ippolito <bob@redivi.com>,
        Marius Eriksen <marius@monkey.org>,
        Alex Brasetvik <alex@brasetvik.com>,
        Alden Jackson <awjacks@bbn.com>
        """

def make_hashfuncs_orig(num_slices, num_bits, my_hash_salts=None):
    """
    The original hash functions
    """

    if num_bits >= (1 << 31):
        fmt_code, chunk_size = 'Q', 8
    elif num_bits >= (1 << 15):
        fmt_code, chunk_size = 'I', 4
    else:
        fmt_code, chunk_size = 'H', 2

    total_hash_bits = 8 * num_slices * chunk_size

    if total_hash_bits > 384:
        hashfn = hashlib.sha512
    elif total_hash_bits > 256:
        hashfn = hashlib.sha384
    elif total_hash_bits > 160:
        hashfn = hashlib.sha256
    elif total_hash_bits > 128:
        hashfn = hashlib.sha1
    else:
        hashfn = hashlib.md5
    
    fmt = fmt_code * (hashfn().digest_size // chunk_size)
    num_salts, extra = divmod(num_slices, len(fmt))

    if extra:
        num_salts += 1

    salts = [hashfn(hashfn(struct.pack('I', i)).digest())
            for i in xrange(num_salts)]

    def _make_hashfuncs(key):
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        else:
            key = str(key)
        rval = []

        for salt in salts:
            h = salt.copy()

            h.update(key)
            rval.extend(uint % num_bits
                    for uint in struct.unpack(fmt, h.digest()))

        del rval[num_slices:]
        return rval

    return _make_hashfuncs, my_hash_salts

def make_hashfuncs_smoosh1(num_slices, num_bits, my_hash_salts=None):
    """
    The smoosh1 version of hashfuncs

    TODO: make sure the random number generator is seeded properly.
    """

    num_salts = num_slices

    # print 'num_salts =', num_salts, ' num_bits =', num_bits

    # Create new salts randomly, if they are not provided
    #
    if not my_hash_salts:
        my_hash_salts = [random.randint(1, 0x7fffffff)
                for _ind in xrange(num_salts)]

    functions = [cb.util.smoosh1_hash.smoosh1_hash_seeded(salt)
            for salt in my_hash_salts]

    #print len(salts), my_hash_salts, functions

    def _make_hashfuncs(key):
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        else:
            key = str(key)
        rval = []

        # print num_bits*num_slices, int(math.ceil( math.log(num_bits*num_slices, 2)))
        # print 'key, len(key) = ', key, len(key)

        # would prefer not to re-calculate this parameter...
        hash_size = int(math.ceil( math.log(num_bits*num_slices, 2)))
        hash_mask = 0xffffffff >> (32 - hash_size)

        for function in functions:
            # print 'function(key) =', function(key), 'function(key)%num_bits
            # =', function(key) % num_bits, 'function(key)&hash_mask =',
            # function(key) & hash_mask
            '''
            make this a shift over a mod

            was:
            rval.append(salt(key) % num_bits)
            now:
            '''
            rval.append(function(key) & hash_mask)

        del rval[num_slices:] 
        # print "number of hashes =", len(rval), ", hash values =", rval
        return rval

    return _make_hashfuncs, my_hash_salts


class CB_BloomFilter(object):
    FILE_FMT = '<dQQQQQ'

    def __init__(self, capacity, error_rate=0.001):
        """Implements a space-efficient probabilistic data structure optimized
           for the number of hashes required

        capacity
        this BloomFilter must be able to store at least *capacity* elements
            while maintaining no more than *error_rate* chance of false
            positives. 
        error_rate
            the error_rate of the filter returning false positives. This
            determines the filters capacity. Inserting more than capacity
            elements greatly increases the chance of false positives.
        num_slices
            smaller than what normal Bloom filters require for error_rate,
            because twice the memory(M) is used
        num_bits
            twice the size of what a normal Bloom filter would be in order
            to reduce the number of hashes required

        >>> b = CB_BloomFilter(capacity=100000, error_rate=0.001)
        >>> b.add("test")
        False
        >>> "test" in b
        True

        """
        # set error_rate = 1e-6

        # for now the error_rate is hard coded for 1e-6
        # until a closed form to find k, the number of hashes is
        # implemented
        error_rate = 1e-6

        if not (0 < error_rate < 1):
            raise ValueError("Error_Rate must be between 0 and 1.")
        if not capacity > 0:
            raise ValueError("Capacity must be > 0")

        # This code gives each hash a range of M/k bits disjoint from
        # all the others, as opposed to using one array of size M shared
        # among all the hashes.
        #
        # The DR code does the latter, so this will have to change.
        #
        # First calculate the correct parameters for a standard bloom
        # filter.

        # given M = num_bits, k = num_slices, p = error_rate, n = capacity
        # solving for m = bits_per_slice
        # n ~= M * ((ln(2) ** 2) / abs(ln(P)))
        # n ~= (k * m) * ((ln(2) ** 2) / abs(ln(P)))
        # m ~= n * abs(ln(P)) / (k * (ln(2) ** 2))
        num_slices = int(math.ceil(math.log(1 / error_rate, 2)))
        bits_per_slice = int(math.ceil(
            (capacity * abs(math.log(error_rate))) /
            (num_slices * (math.log(2) ** 2))))
        
        # Then change the parameters, assuming the memory size is at
        # least doubled for the same error_rate.  This permits reducing
        # the number of required hashes to achieve the same error_rate,
        # e.g., from 20 hashes to 6 hashes for error_rate = 1e-6.

        # we set num_slices to new value based on doubling the memory and
        # error_rate = 1e-6
        # need closed form solution to calculate k, where cb_num_slices = k
        # ln(error_rate) = (1 - exp(-alpha*k))**k, where alpha = n/M
        cb_num_slices = 6

        # Now double the size of the Bloom filter and adjust
        # the size of the array to the next largest power of
        # 2 (to meet the DR's requirements) and recalculate the
        # bits/slice.  As long as the filter size is the same or
        # increases, then the resulting bloom filter will false
        # positive performance no worse then error_rate

        #print 'exponent', int(math.ceil(
        #                    math.log(2 * num_slices * bits_per_slice,2)))
        #print 'new size of array', (1 << int(math.ceil(
        #                    math.log(2 * num_slices * bits_per_slice,2))))
        cb_bits_per_slice = int(math.ceil(
                (1 << int(math.ceil(
                            math.log(2 * num_slices * bits_per_slice,2)))) /
                cb_num_slices))
        # awj debug
        # print "2 * num_slices * bits_per_slice = ", 2 * num_slices * bits_per_slice
        # print "cb_bits_per_slice = ", cb_bits_per_slice
        

        hash_size = int(
                math.ceil(math.log(cb_num_slices * cb_bits_per_slice, 2)))

        self._setup(error_rate, cb_num_slices, cb_bits_per_slice, capacity, 0,
                hash_size)

        self.bitarray = bitarray.bitarray(self.num_bits, endian='little')
        self.bitarray.setall(False)

    def _setup(self, error_rate, num_slices, bits_per_slice, capacity, count,
            hash_size):
        self.error_rate = error_rate
        self.num_slices = num_slices
        self.bits_per_slice = bits_per_slice
        self.capacity = capacity
        self.hash_size = hash_size

        # TODO: some of these parameters are mutually dependent: for
        # example, hash_size should be:
        # int(math.ceil(math.log(num_slices * bits_per_slice, 2)))
        # If it's not, we should gripe.

        self.num_bits = 1 << self.hash_size
        # self.num_bits = num_slices * bits_per_slice
        self.count = count
        self.make_hashes, self.salts = make_hashfuncs_smoosh1(
                self.num_slices, self.bits_per_slice)

    def __str__(self):
        '''
        create a human readable string describing a CB_BloomFilter

        the string will not contain a listing of the BF data, but will
        include the bitarray.buffer_info()
        '''
        text = '{FILE_FMT: %s,' % self.FILE_FMT
        if self.error_rate != None:
            text += ' error_rate: %G,' % self.error_rate
        else:
            text += ' error_rate: %s,' % self.error_rate

        text += ' num_slices: %u,' % self.num_slices
        text += ' bits_per_slice: %u,' % self.bits_per_slice
        text += ' capacity: %u,' % self.capacity
        text += ' hash_size: %u,' % self.hash_size
        text += ' num_bits: %u,' % self.num_bits
        text += ' count: %u,' % self.count
        text += ' len(salts): %u,' % len(self.salts)
        text += ' salts: %s,' % self.salts
        text += ' bitarray.buffer_info(): %s}' % (self.bitarray.buffer_info(), )
        
        return text

        
    def __contains__(self, key):
        """Tests a key's membership in this bloom filter.

        >>> b = CB_BloomFilter(capacity=100)
        >>> b.add("hello")
        False
        >>> "hello" in b
        True

        """

        bits = self.bitarray

        if not isinstance(key, list):
            hashes = self.make_hashes(key)
        else:
            hashes = key

        # print 'len(bits) =', bits.length(), 'hashes =', hashes
        for k in hashes:
            # no longer using k disjoint sections of array
            if not bits[k]:
                return False
        return True

    def __len__(self):
        """Return the number of keys stored by this bloom filter."""
        return self.count

    def add(self, key, skip_check=False):
        """ Adds a key to this bloom filter. If the key already exists in this
        filter it will return True. Otherwise False.

        >>> b = CB_BloomFilter(capacity=100)
        >>> b.add("hello")
        False
        >>> b.add("hello")
        True
        """

        bits = self.bitarray
        hashes = self.make_hashes(key)
        if not skip_check and hashes in self:
            return True
        if self.count > self.capacity:
            raise IndexError("BloomFilter is at capacity")
        
        for k in hashes:
            # no longer using k disjoint sections of array
            bits[k] = True
        self.count += 1
        return False

    def copy(self):
        """Return a copy of this bloom filter.
        """
        new_filter = CB_BloomFilter(self.capacity, self.error_rate)
        new_filter.bitarray = self.bitarray.copy()
        return new_filter

    def union(self, other):
        """ Calculates the union of the two underlying bitarrays and returns
        a new bloom filter object."""
        if self.capacity != other.capacity or \
            self.error_rate != other.error_rate:
            raise ValueError("Unioning filters requires both filters to have \
both the same capacity and error rate")
        new_bloom = self.copy()
        new_bloom.bitarray = new_bloom.bitarray | other.bitarray
        return new_bloom

    def __or__(self, other):
        return self.union(other)

    def intersection(self, other):
        """ Calculates the union of the two underlying bitarrays and returns
        a new bloom filter object."""
        if self.capacity != other.capacity or \
            self.error_rate != other.error_rate:
            raise ValueError("Intersecting filters requires both filters to \
have equal capacity and error rate")
        new_bloom = self.copy()
        new_bloom.bitarray = new_bloom.bitarray & other.bitarray
        return new_bloom

    def __and__(self, other):
        return self.intersection(other)

    def tofile(self, f):
        """Write the bloom filter to file object `f'. Underlying bits
        are written as machine values. This is much more space
        efficient than pickling the object."""
        f.write(struct.pack(self.FILE_FMT, self.error_rate, self.num_slices,
                     self.bits_per_slice, self.capacity, self.count,
                     self.hash_size))

        # After the ordinary header, write out the salt header:
        # The number of salts, followed by each individual salt.
        #
        f.write(struct.pack('<L', len(self.salts)))
        for salt in self.salts:
            f.write(struct.pack('<L', salt))

        self.bitarray.tofile(f)

    def tofile_simple(self, f):
        """ Write only the bitarray of the bloom filter to a file
        object 'f'. Underlying bits are written as machine values.
        When the length of the bitarray is not a multiple of 8, the
        remaining bits (1..7) are set to 0."""
        self.bitarray.tofile(f)
    
    def to01(self):
        """
        Return only the bitarray of the bloom filter to a string
        containing '0's and '1's, representing the bits in the bitarray
        object.
        """
        return self.bitarray.to01()
    
    def match_any(self):
        """ Make this bloom filter return True to any input. """
        self.bitarray[:] = True

    def match_none(self):
        """ Make this bloom filter return False to all input. """
        self.bitarray[:] = False

    @classmethod
    def fromfile(cls, f, n=-1):
        """Read a bloom filter from file-object `f' serialized with
        ``CB_BloomFilter.tofile''. If `n' > 0 read only so many bytes."""
        headerlen = struct.calcsize(cls.FILE_FMT)

        if 0 < n < headerlen:
            raise ValueError, 'n too small!'

        bfilter = cls(1)  # Bogus instantiation, we will `_setup'.
        bfilter._setup(*struct.unpack(cls.FILE_FMT, f.read(headerlen)))

        # TODO:
        # Now we read in the length of the salts, and then read each salts.
        # Once we have the list of salts, we call make_hashfuncs with the
        # correct salts and replace bfilter.make_hashes and bfilter.salts
        # with the correct values.
        #
        # TODO: any read exceptions should be caught and turned into
        # ValueErrors to indicate that the file is corrupt/truncated.
        #

        long_fmt = '<L'
        long_fmt_size = struct.calcsize(long_fmt)
        num_salts = struct.unpack(long_fmt, f.read(long_fmt_size))[0]
        salts = [ struct.unpack(long_fmt, f.read(long_fmt_size))[0]
                for _ind in xrange(num_salts) ]
        bfilter.make_hashes, bfilter.salts = make_hashfuncs_smoosh1(
                bfilter.num_slices, bfilter.bits_per_slice, salts)

        bfilter.bitarray = bitarray.bitarray(endian='little')
        if n > 0:
            bfilter.bitarray.fromfile(f, n - headerlen)
        else:
            bfilter.bitarray.fromfile(f)
        if bfilter.num_bits != bfilter.bitarray.length() and \
               (bfilter.num_bits + (8 - bfilter.num_bits % 8)
                != bfilter.bitarray.length()):
            raise ValueError, 'Bit length mismatch!'

        return bfilter

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['make_hashes']
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)
        self.make_hashes = make_hashfuncs_smoosh1(
                self.num_slices, self.bits_per_slice)



#if __name__ == "__main__":
#    import doctest
#    doctest.testmod()

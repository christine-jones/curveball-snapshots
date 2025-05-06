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


# FIXME: convert to use tlslite?
"""
Implementation of the subset of the data record protocol of SSL 3.1, aka TLS.

We only support connections with a cipher of AES256 and an HMAC of SHA-1.

The block size of AES256 is 16 bytes, and the size of the SHA-1 digest
is 20 bytes, so these are constants in our implementation.
"""

import hashlib
import hmac
import logging
import re
import struct
import binascii
import sys
import tlslite.constants as tconst

import cb.util.cblogging

# FIXME
# often one wants to replace DEBUG and debug(...) with self.log.debug(...)
import os
DEBUG = int(os.getenv("DEBUG_CURVEBALL", "0"))

def log_debug(msg):
    print >> sys.stderr, "CT_DP2/cssl: %s" % msg

def log_info(msg):
    print >> sys.stderr, "CT_DP2/cssl: %s" % msg

# FIXME
# and replace DEBUG and warn with self.log.warn
def log_warn(msg):
    log_debug(msg)


# FIXME
# and replace log_error with self.log.warn
def log_error(msg):
    print >> sys.stderr, "CT_DP2/cssl: %s" % msg

class HMacError(Exception):
    """Base class for exceptions in this module."""
    pass


class CurveballTLS(object):
    """
    Wrapper for TLS data record operations ala Curveball.
    """

    # ContentType type (byte)
    #
    # ProtocolVersion version (byte-major, byte-minor)
    #
    # PayloadLength length (uint16)
    #
    TLS_RECORD_HEADER_FMT = '!BBBH'
    TLS_RECORD_HEADER_LEN = struct.calcsize(TLS_RECORD_HEADER_FMT)

    # Assuming 16B cipher block, HMAC=SHA-1
    #
    CIPHER_BLOCK_SIZE = 16
    HMAC_SIZE = 20
    MAX_DATA_PER_RECORD = 4096

    def __init__(self):
        """
        Initialize the curveball TLS endpoint.
        """

        self.log = logging.getLogger('cb.cssl')
        self._seqno = 0
        self._hmac_key = None
        self._hmac = None
        self._cipher = None

        # This is used for debugging CBC streams --- we remember the
        # last ciphertext block sent/received so we can double-check
        # the crypto state at each end.
        self._iv_memo = '?' * 16

    def sequence_number_set(self, seqno):
        self._seqno = seqno

    def hmac_key_set(self, key):
        self._hmac_key = key

    def cipher_set(self, cipher, iv=('?' * 16)):
        """
        Assign a cipher to use in this direction.  It should be the
        sort of thing returned by
        TLSflow.crypto.createCipherFunc(session_key, iv)

        If you need to change the key for the cipher, you must create a new
        cipher instance and install it with this method.
        """
        self._cipher = cipher
        self._iv_memo = iv

    # FIXME: almost all the errors here should kill the connection,
    # what they do now is send us off into an infinite loop because we
    # keep returning to this same data
    # Also: most of those errors are the result of getting the key
    # wrong.  We'll never recover.
    #
    # FIXME: Rewrite this using tlslite
    def get_next_data_record(self,
                             buf,
                             check_hmac=True,
                             check_pad=True,
                             do_decrypt=True,
                             check_len=True):
        """
        check_hmac - confirm that the digest matches the data (note that we
        don't really use an HMAC right now; it's just a simple digest)

        check_pad - confirm that the pad is correct

        do_decrypt - decrypt the data.  Must be True or else check_hmac and
        check_pad don't make sense and won't work.  In this case, returns the
        raw encrypted data from the data record.

        check_len - rejects messages that aren't an integral number of cipher blocks long.
        """

        if len(buf) < self.TLS_RECORD_HEADER_LEN:
            log_info('Partial data (got %d wanted %d) (too short for TLS record header)' %
                     (len(buf), self.TLS_RECORD_HEADER_LEN))
            return None

        header_len = self.TLS_RECORD_HEADER_LEN

        header = buf[:header_len]
        (content_type, version_major, version_minor, data_len) = \
                struct.unpack(self.TLS_RECORD_HEADER_FMT, header)

        if len(buf) < (self.TLS_RECORD_HEADER_LEN + data_len):
            log_info('Partial data (got %d wanted %d)' %
                    (len(buf), self.TLS_RECORD_HEADER_LEN + data_len,))
            return None

        # alert message
        if content_type == tconst.ContentType.alert:
            # data_len field says "2", but the data len does not take
            # into account mac nor padding
            # FIXME: for now, if encrypting, assume data_len is 32
            # FIXME: handle unencrypted case?  Though the architecture
            # of the symmetric handshake is such that we don't get
            # here unless we've already done a key exchange.
            log_info('TLS ALERT message!! Encrypted: assuming data-len is 32')
            data_len = 32
            process_alert = True
            check_pad = False
            check_hmac = False
        else:
            process_alert = False
        # end if content_type == tconst.ContentType.alert

        if(content_type != tconst.ContentType.alert
           and content_type != tconst.ContentType.application_data):
            log_info('Not a data record (type = %d)' % content_type)
            return None

        if (version_major != 3) or (version_minor != 1):
            log_info('Not SSL 3.1 (version = %d.%d)' %
                    (version_major, version_minor))
            return None

        if data_len > (1 << 14):
            log_info('Nonsense length: too large (%u)' % (data_len,))
            return None

        # First we must decrypt
        #
        if (not do_decrypt) or (self._cipher == None):
            plaintext_data = buf[header_len:header_len + data_len]
        else:
            # We assume that we're always using a block-cipher.
            #
            # If the data_len isn't a multiple of the cipher block size, then it's
            # obviously bogus.  Bail out.
            #
            if check_len and (data_len % self.CIPHER_BLOCK_SIZE) != 0:
                log_info('Bogus length: not multiple of block size (%u)' %
                        (data_len,))
                return None

            crypt_data = buf[header_len:header_len + data_len]

            DEBUG and log_debug('AES CBC IV (dec): %s'
                                % binascii.hexlify(self._iv_memo))
            DEBUG and log_debug('cyphertext: %s'
                                % binascii.hexlify(crypt_data))

            plaintext_data = self._cipher.decrypt(crypt_data)
            # update IV for next block (this is for those times when
            # we have to debug talking to different ciphers)
            self._iv_memo = crypt_data[-self.CIPHER_BLOCK_SIZE:0]

            app_data = plaintext_data
            hmac_data = ''
            pad_data = ''

            pad_len = ord(plaintext_data[-1:])
            if check_hmac:
                hmac_len = self.HMAC_SIZE
            else:
                hmac_len = 0

            if check_pad:
                # Is there more padding than will actually fit?  That's a problem.
                #
                if (pad_len + hmac_len) > data_len:
                    log_info('Bogus pad_len %u (hmac_len %u data_len %u)' %
                             (pad_len, self.HMAC_SIZE, data_len))
                    DEBUG and log_debug('plaintext (len %d): [%s]'
                                        % (len(plaintext_data),
                                           binascii.hexlify(plaintext_data)))
                    return None

                pad_data = plaintext_data[-(pad_len + 1):-1]
                if len(pad_data) != pad_len:
                    self.log.warn('My math is wrong')
                    return None

                # Check that the pad is correct.
                #
                # We could make this optional.  It might be annoying to always have
                # to get the padding right; we could use this space for metadata.
                #
                for index in range(0, len(pad_data)):
                    if ord(pad_data[index]) != pad_len:
                        log_info('Bogus pad (index %d, value %u, wanted %u)' %
                                 (index, ord(pad_data[index]), pad_len))
                        DEBUG and log_debug('plaintext (len %d): [%s]'
                                            % (len(plaintext_data),
                                               binascii.hexlify(plaintext_data)))
                        return None
                    # end if ord(pad_data...)
                # end for
            # end if
            if check_hmac:
                hmac_data = plaintext_data[-(1 + pad_len + self.HMAC_SIZE)
                                            :-(1 + pad_len)]

                app_data = plaintext_data[:-(1 + pad_len + self.HMAC_SIZE)]
                
                if ((len(app_data) + len(hmac_data) + len(pad_data) + 1)
                    != len(plaintext_data)):
                    self.log.warn('My math is wrong again')
                    return None
                # end if (len(app_data) ....

                # OK, nothing was visibly wrong.
                #
                # Return the data and the number of bytes that we consumed from the
                # input.
                # look at ssl3_CompressMACEncryptRecord in
                # src/nss/nss-3.12.9/mozilla/security/nss/lib/ssl/ssl3con.c
                #
                # If version is <= SSL_3_0:
                #     temp = struct.pack('!QBBB',
                #                        seq#,
                #                        type (0x17 for application data)
                #                        2 bytes of len(app_data))
                # else:
                #     temp = struct.pack('!QBBBBB',
                #                        seq#,
                #                        type (0x17 for application data)
                #                        2 bytes of 0x301,
                #                        2 bytes of len(app_data))
                #
                temp = struct.pack('!QBBBBB', self._seqno,
                                   content_type, version_major, version_minor,
                                   (len(app_data)>>8)&0xff, len(app_data) & 0xff)

                # sha1_engine = hashlib.sha1()
                # sha1_engine.update(temp)
                # sha1_engine.update(app_data)
                # sha1_app_data = sha1_engine.digest()
                if self._hmac_key:
                    hm = hmac.new(str(self._hmac_key), digestmod = hashlib.sha1)
                    hm.update(temp)
                    hm.update(app_data)
                    sha1_app_data = hm.digest()

                    if sha1_app_data != hmac_data:
                        # HMAC check failed
                        self.log.warn('failed hmac')
                        raise Exception("Failed HMAC --- seqno %d"
                                        % self._seqno)


                # time to increment the sequence number
                self._seqno += 1
            # end if check_hmac

        if do_decrypt:
            if process_alert:
                app_data = plaintext_data[0:2]
                log_warn('TLS ALERT: level %d; description %d'
                         % (ord(app_data[0]), ord(app_data[1])))

                print('TLS ALERT: level %d; description %d'
                         % (ord(app_data[0]), ord(app_data[1])))
            else:
                app_data = plaintext_data[:-(pad_len + 1 + self.HMAC_SIZE)]
        else:
            app_data = plaintext_data

        return (app_data, self.TLS_RECORD_HEADER_LEN + data_len)


    def encrypt_data_record(self, record):
        """
        This function is used when we want to encrypt a
        data record in order to keep the cipher state in
        the right state, but we aren't actually doing
        anything with the encrypted output
        """
       
        self._cipher.encrypt(record)
        self._seqno += 1
        
    def create_data_record(self, app_data, printcipher=False):
        # TODO: MAKE SURE THAT THE app_data IS SHORT ENOUGH
        if self._hmac_key:
            temp = struct.pack('!QBBBBB', self._seqno,
                               23, 3, 1,
                               (len(app_data)>>8) & 0xff,
                               len(app_data) & 0xff)

            hm = hmac.new(str(self._hmac_key), digestmod = hashlib.sha1)

            DEBUG and log_debug('hmac key: [%s]' % binascii.hexlify(self._hmac_key))
            DEBUG and log_debug('seqno: %s' % str(self._seqno))
            DEBUG and log_debug('hmac input0: [%s]' % binascii.hexlify(temp))
            DEBUG and log_debug('hmac input1: [%s]' % binascii.hexlify(app_data))
        
            hm.update(temp)
            hm.update(app_data)
            hmac_data = hm.digest()
            DEBUG and log_debug('hmac output: [%s]' % binascii.hexlify(hmac_data))
        else:
            sha1_engine = hashlib.sha1()
            sha1_engine.update(app_data)
            hmac_data = sha1_engine.digest()

        self._seqno += 1

        scratch_data = app_data + hmac_data
        total_data_needed = len(scratch_data) + 1
        rem = total_data_needed % self.CIPHER_BLOCK_SIZE

        # We're not doing anything here to be sneaky.  It is advised that
        # adding extra padding blocks is sometimes a good thing.
        # TODO: be sneaky --- one bit of sneakiness would be to make this
        # record be the same size as the record sent by the DH, now that we're
        # in a position to observe that.
        if rem != 0:
            padding_len = self.CIPHER_BLOCK_SIZE - rem
            padding = chr(padding_len) * (1 + padding_len)
        else:
            padding_len = 0
            padding = '\0'

        scratch_data += padding

        DEBUG and log_debug('AES CBC IV (enc): %s'
                            % binascii.hexlify(self._iv_memo))
              
        ciphertext = self._cipher.encrypt(scratch_data)
        DEBUG and log_debug('ciphertext: %s'
                            %binascii.hexlify(ciphertext))
        
       
        self._iv_memo = ciphertext[-self.CIPHER_BLOCK_SIZE:]
        
        if len(ciphertext) > (1 << 14):
            log_info('Nonsense length. (%u)' % (len(ciphertext),))
            return None

        # magic numbers: data record, TLS 3.1 version numbers.
        #
        header = struct.pack(self.TLS_RECORD_HEADER_FMT,
                             23,
                             3,
                             1,
                             len(ciphertext))

        if printcipher:
            print ('CIPHERTEXT (len %d): [%s]'
                   % (len(ciphertext), binascii.hexlify(ciphertext)))
        record = header + ciphertext
        return record

    def create_data_records(self, app_data, max_data_per_record=4096):
        """
        Given a string of app_data, create as many data records as necessary to
        represent the app_data.

        The payload length of a TLS data record is 16KB, but because the record
        has extra padding, encryption, and an HMAC, etc, it's not easy to know
        exactly how much of the app_data we can stuff in each one.  So what we
        do is punt and choose a size that is guaranteed to work:
        max_data_per_record.

        TODO this is lame because it makes our streams easy to fingerprint.
        """

        records = []

        while app_data != '':
            head = app_data[:max_data_per_record]

            records.append(self.create_data_record(head))

            app_data = app_data[max_data_per_record:]

        return records

    @staticmethod
    def is_record(ssl_data, record_type=tconst.ContentType.application_data):
        """
        Check whether a prefix of ssl_data is a valid TLS record of
        the given type.
        """

        prefix = record_type + '\3\1'

        if len(ssl_data) < 5:
            return False

        if not ssl_data.startswith(prefix):
            return False

        rec_len = (ord(ssl_data[3]) << 8) + ord(ssl_data[4])

        if rec_len > (1 << 14):
            return False


    @staticmethod
    def find_record_start(ssl_data):
        """
        Heuristic search for the start of a TLS data record.

        Returns the offset to the start of the first thing that looks like it
        might be a TLS data record.  There are enough tell-tales in the header
        to make this reasonably likely.  Returns -1 if no plausible offset is
        found.
        """

        offset = 0
        app_pattern = '\27\3\1'
        alert_pattern = '\25\3\1'

        while 1:
            match = re.search(app_pattern, ssl_data)
            if not match:
                match = re.search(alert_pattern, ssl_data)
                if match:
                    # the header says the payload len is 2, even when
                    # there's a MAC and padding added (it probably is
                    # 2 if we're not yet encrypted, but if we're not
                    # yet encrypted, we're probably not running this
                    # code).
                    payload_len = 32
                else:
                    return -1

            start = match.start()

            # We can't be less than 5 bytes header, 1 byte data, 20 bytes hash,
            # and 1 byte pad length.  (in fact, we probably can't really be less
            # than 5 bytes header plus 32 bytes encrypted payload because the
            # encrypted data is always larger than the input.
            #
            if len(ssl_data) < (start + 27):
                return -1

            # Additional heuristic: lengths can't be greater than 16KB, so the
            # high byte must be less than or equal to 0x40.
            #
            # TODO: check whether it's < or <=
            #
            # TODO: sloppy: if the len of ssl_data is less than match.end, then
            # kaboom.
            #
            hilen = ord(ssl_data[match.end()])
            lolen = ord(ssl_data[match.end() + 1])
            if hilen >= 0x40:
                next

            payload_len = (hilen << 8) + lolen

            if len(ssl_data) >= (5 + payload_len):
                return offset + start

            # we failed.  try again.
            ssl_data = ssl_data[match.end():]
            offset += match.end()


    def parse_data_records(self, ssl_data, find_start=False):
        """
        Given a string or buffer representing the contents of an TLS stream,
        parse it into as many TLS records as possible, pull out the app data,
        and concatenate it.

        If find_start is True, then instead of assuming that the start of the
        buffer is the start of the first record, search for something that looks
        like a valid record header in the buffer.

        Returns (start, app_data, remainder, data_chunks) where start is the
        offset into the buffer of the first record (which will be 0 unless
        find_start is True, and probably 0 even then), app_data is a string
        containing the app data from the ssl_data, and remainder is any
        unprocessed ssl_data.  data_chunks are the pieces of the data from each
        data record; these are useful for debugging but not much else.

        If no records can be parsed, then this routine will return (0, '',
        ssl_data, []).  It might throw an exception if something really bad
        happens.

        TODO: tighten up this spec.
        """

        if find_start:
            start = self.find_record_start(ssl_data)
            if start < 0:
                return (0, '', ssl_data, [])
            elif start > 0:
                ssl_data = ssl_data[start:]
        else:
            start = 0

        data_chunks = []
        remainder = ssl_data
        
        while remainder != '':
            parse = self.get_next_data_record(remainder)
            if not parse:
                break
            else:
                (data_chunk, consumed) = parse
                remainder = remainder[consumed:]
                data_chunks.append(data_chunk)

        app_data = ''.join(data_chunks)
        return (start, app_data, remainder, data_chunks)


# FIXME --- rewrite for a scheme that (like SSL), calls for different
# keys in each direction.

# if __name__ == '__main__':
#     from cb.cssl.aes import CurveballAES256_ECB
#     from cb.cssl.aes import CurveballAES256_CBC

#     def make_cssl(key, mode):
#         """
#         Make a fresh cssl engine of the given mode (cbc or ecb)
#         """

#         if mode == 'cbc':
#             return CurveballTLS(CurveballAES256_CBC(key))
#         elif mode == 'ecb':
#             return CurveballTLS(CurveballAES256_ECB(key))
#         else:
#             return None

#     def test_mode(mode):
#         """ test main """

#         key = '4' * 32

#         ptexts = [
#                 'short',
#                 'this is sixteen.',
#                 'here is something',
#                 'here is something a little longer',
#                 'here is something in the middle',
#                 'here is exactly len thirty---two',
#                 'here is something random',
#                 'here is something long enough to span two blocks',
#                 'here is something that should be long enough to span' +
#                     ' into a third block, if my calculations are correct'
#                 ]
#         ctexts = []
#         dtexts = []
#         cstream = ''

#         cssl = make_cssl(key, mode)

#         for text in ptexts:
#             ctext = cssl.create_data_record(text)
#             ctexts.append(ctext)
#             cstream += ctext

#         for text in ctexts:
#             (dtext, _dtext_len) = cssl.get_next_data_record(text)
#             dtexts.append(dtext)

#         attempts = 0
#         successes = 0
#         for index in range(0, len(ptexts)):
#             attempts += 1
#             if (ptexts[index] == dtexts[index]
#                 and len(ptexts[index]) == len(dtexts[index])):
#                 successes += 1

#         cssl = make_cssl(key, mode)

#         (base, _app_data, remainder, chunks) = cssl.parse_data_records(cstream)
#         if base != 0:
#             attempts += 1
#         elif remainder != '':
#             attempts += 1
#         else:
#             for index in range(0, len(ptexts)):
#                 attempts += 1
#                 if (ptexts[index] == chunks[index]
#                     and len(ptexts[index]) == len(chunks[index])):
#                     successes += 1

#         cssl = make_cssl(key, mode)

#         junk_prefix = 'junk!'
#         bad_data = junk_prefix + cstream
#         (base, _app_data, remainder, chunks) = cssl.parse_data_records(
#                 bad_data, find_start=True)
#         if base != len(junk_prefix):
#             attempts += 1
#         elif remainder != '':
#             attempts += 1
#         else:
#             for index in range(0, len(ptexts)):
#                 attempts += 1
#                 if(ptexts[index] == chunks[index]
#                    and len(ptexts[index]) == len(chunks[index])):
#                     successes += 1

#         cssl = make_cssl(key, mode)

#         junk_prefix = 'junk!'
#         junk_suffix = 'bad suffix'
#         bad_data = junk_prefix + cstream + junk_suffix
#         (base, _app_data, remainder, chunks) = cssl.parse_data_records(
#                 bad_data, find_start=True)
#         if base != len(junk_prefix):
#             attempts += 1
#         elif remainder != junk_suffix:
#             attempts += 1
#         else:
#             for index in range(0, len(ptexts)):
#                 attempts += 1
#                 if (ptexts[index] == chunks[index]
#                     and len(ptexts[index]) != len(chunks[index])):
#                     successes += 1

#         if (attempts > 0) and (attempts == successes):
#             return 0
#         else:
#             return 1

#     exit(test_mode('ecb') | test_mode('cbc'))



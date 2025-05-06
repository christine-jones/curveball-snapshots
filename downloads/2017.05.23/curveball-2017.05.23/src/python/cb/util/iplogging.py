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

""" The Curveball Logging Setup
    Use names like: 'ip', 'ip.tcphijack', 'ip.dr2dp', etc..
    
    You only need to import this module once in your program,
    but multiple imports won't hurt
    
    The log file rotates each instantiation so you can compare
    the current log file to previous runs.  Currently it only
    saves 1 backup, but this can be changed with the backupCount
    parameter.
"""

import logging
import logging.handlers
import os.path
import sys

class CurveballIpLogger(object):
    """
    Wrapper class to keep the global namespace clean.

    Almost identical to CurveballLogger; see it for more detail.
    """

    LOG_SUFFIX = '.log'

    @staticmethod
    def choose_filename():
        """
        Create a filename for the log file from sys.argv[0].

        Even if sys.argv[0] points to another directory, we always create the
        log in the current working directory.

        Assumes that nobody has clobbered sys.argv[0].
        """

        (_head, tail) = os.path.split(sys.argv[0])

        if not tail:
            # Can this even happen?  If it does, punt.
            tail = 'CurveballIpLogger'

        (root, _ext) = os.path.splitext(tail)

        return './%s-ip%s' % (root, CurveballIpLogger.LOG_SUFFIX)

    @staticmethod
    def init_logger(filename='', loggername='ip',
            level=logging.DEBUG, backup_count=1, want_stream=False):
        """
        Initialize a logger for this process.

        filename - the file to store the default logger.  If a filename
            is not supplied or is '', then a name in the working directory,
            based on the name of the script with .log append, is used
            (Assuming that nobody has clobbered sys.argv[0])

        loggername - the name of the logger.  This should be the prefix
            that all of the other loggers are going to use.  The default
            is 'cb'.

        level - the active logging level

        backup_count - how many previous copies of the log file to keep

        want_stream - if non-False, add a Stream handler in addition to the
            RotatingFile handler.

        """

        if not filename:
            filename = CurveballIpLogger.choose_filename()

        # Set up a specific logger with our desired output level
        logger = logging.getLogger(loggername)
        logger.setLevel(level)

        # Add the log message handler to the logger
        handler = logging.handlers.RotatingFileHandler(
                      filename, backupCount=backup_count)

        formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)d ' +
                '%(message)s')

        handler.setFormatter(formatter)

        # Start a fresh log file each run
        handler.doRollover() 

        logger.addHandler(handler)

        # If you want a stream handler...
        #
        if want_stream:
            serr = logging.StreamHandler()
            logger.addHandler(serr)

        # After we create the logger, I think we need need to stash a reference
        # to it somewhere so we don't lose it.  It might hang around in a
        # private namespace whether we do this or not, but this isn't too gross
        # because this puts it in a class-scope variable, so the global
        # namespace is untouched.
        #
        CurveballIpLogger.logger = logger

    @staticmethod
    def log_str(pkt, comment=''):
        """
        Express the given pkt in 'log' format, which has four fields (the fourth
        of which is optional), separated by spaces.

        The first field is the ipid of the pkt, expressed as a 16-bit hex
        number (left-padded with zeros, if necessary)

        The second field is the length of the pkt, in bytes, expressed as an
        unsigned decimal number.

        The third field is a string of hex duets representing the binary of the
        pkt.

        The fourth field is the comment string.  The comment string may contain
        space characters, but should not contain newlines (or else parsing the
        log files becomes much more awkward).  No constraints on the contents of
        the comment string are enforced; very silly things are possible.

        The pkt must be correctly expressed as a string or buffer, although this
        method is not fussy and will try to do something sensible.
        """

        # This is strange.  This IP pkt doesn't even have a complete
        # header.  Pad it with zeros.
        #
        if len(pkt) < 20:
            pkt += (chr(0) * (20 - len(pkt)))

        pkt_str = str(pkt)
        pkt_hex = ''.join(['%.2x' % ord(byte) for byte in pkt_str])

        trailer = ''
        if comment:
            trailer += ' %s' % (comment,)

        ipid = pkt_hex[8:12]

        return '%s %u %s%s' % (ipid, len(pkt_str), pkt_hex, trailer)


CurveballIpLogger.init_logger()

if __name__ == '__main__':
    # This is for eyeball use only
    #
    print 'I would use logger file (%s)' % (
            CurveballIpLogger.choose_filename(),)

    def test_main():
        """ Test driver """

        test_logger = logging.getLogger('ip.foo')
        test_logger.debug('hellp')
        test_logger.warn('hellp')

        print CurveballIpLogger.log_str('abcdefghijklmn')
        print CurveballIpLogger.log_str('aaaabbccdd')

        return 0

    exit(test_main())


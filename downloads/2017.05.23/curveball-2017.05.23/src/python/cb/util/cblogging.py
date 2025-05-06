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
    Use names like: 'cb', 'cb.tcphijack', 'cb.dr2dp', etc..
    
    You only need to import this module once in your program,
    but multiple imports won't hurt
    
    The log file rotates each instantiation so you can compare
    the current log file to previous runs.  Currently it only
    saves 1 backup, but this can be changed with the backupCount
    parameter.
"""

import errno
import logging
import logging.handlers
import os
import os.path
import socket
import sys

import cb.util.cblogging_setup
import cb.util.platform

class CurveballLogger(object):
    """
    Wrapper class to keep the global namespace clean
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
            tail = 'CurveballLogger'

        (root, _ext) = os.path.splitext(tail)

        return './%s-%s%s' % (root, socket.gethostname(),
                CurveballLogger.LOG_SUFFIX)

    @staticmethod
    def init_logger(filename='', loggername='cb',
            level=logging.WARNING, backup_count=1):
        """
        Initialize a logger for this process.

        The filename and backup_count parameters are interpreted
        according to the value of cb.util.cblogging_setup.LOGTYPE
        at the moment this method is invoked -- for some types
        of loggers, they have no meaning.

        filename - the file to store the file logger.  If a filename
            is not supplied or is '', then a name in the working directory,
            based on the name of the script with .log append, is used
            (Assuming that nobody has clobbered sys.argv[0])

        loggername - the name of the logger.  This should be the prefix
            that all of the other loggers are going to use.  The default
            is 'cb'.

        level - the active logging level

        backup_count - how many previous copies of the log file to keep
        """

        try:
            if os.environ['SSLDEBUG']:
                level = logging.DEBUG
        except KeyError, e:
            # it's okay if the envar is not set
            pass

        # Set up a specific logger with our desired output level
        logger = logging.getLogger(loggername)
        logger.setLevel(level)

        CurveballLogger.logger = logger

        # Android is a special case: if we're on Android, then
        # always use the Android logger
        #
        if cb.util.platform.PLATFORM == 'android':
            add_android()
            return

        logtype = cb.util.cblogging_setup.LOGTYPE

        if logtype == 'syslog':
            add_syslog()
        elif logtype == 'rotfile':
            if not filename:
                filename = CurveballLogger.choose_filename()
            add_rotfile(filename, backup_count)
        elif logtype == 'stderr':
            add_stderr()
        elif logtype == 'stdout':
            add_stdout()
        else:
            assert False, \
                    ('invalid LOGTYPE [%s]' % str(logtype))

def add_android():
    # Initialize android logging if on an Android platform
    #
    assert cb.util.platform.PLATFORM == 'android', \
            'android logger can only be used on Android!'

    import androidhandler

    logging.handlers.AndroidHandler = androidhandler.AndroidHandler
    handler = logging.handlers.AndroidHandler()

    formatter = logging.Formatter(
            '%(asctime)s %(name)s %(module)s:%(lineno)d ' +
            '%(levelname)s: %(message)s')

    handler.setFormatter(formatter)
    CurveballLogger.logger.addHandler(handler)

def add_rotfile(filename, backup_count):

    # TODO - We might want to add the date to the log entries.
    #
    formatter = logging.Formatter(
            '%(asctime)s %(name)s %(module)s:%(lineno)d ' +
            '%(levelname)s: %(message)s')
            #datefmt='%H:%M:%S')

    # Add the log message handler to the logger
    try:
        handler = logging.handlers.RotatingFileHandler(
                filename, backupCount=backup_count)
    except IOError, exc:
        if exc.errno == errno.EACCES:
            print 'ERROR: insufficient privileges to init logfile'
            print 'ERROR: sudo may be necessary'
            sys.exit(1)
    except BaseException, exc:
        print 'ERROR: cannot initialize log file: %s' % str(exc)
        sys.exit(1)

    # Start a fresh log file each run
    handler.doRollover()

    # try to leave the file permissions on the log file such
    # that the next process can modify them, even if it's not
    # root.  This is dangerous.
    #
    if cb.util.platform.PLATFORM in ['android', 'darwin', 'linux2']:
        try:
            os.chmod(filename, 0666)
        except:
            pass

    handler.setFormatter(formatter)
    CurveballLogger.logger.addHandler(handler)

def add_stdout():
    _add_stream(sys.stdout)

def add_stderr():
    _add_stream(sys.stdout)

def _add_stream(stream):
    """
    General stream logger, for stdout or stderr

    We use stdout for some of the daemon-like processes,
    because we haven't gotten around to using syslog properly.
    The assumption is that the scripts responsible for
    managing these processes will redirect the output
    somewhere appropriate.  It isn't usually desirable
    to just dump everything to the terminal.
    """

    handler = logging.StreamHandler(stream=stream)

    formatter = logging.Formatter(
            'cblog %(asctime)s %(name)s %(module)s:%(lineno)d ' +
            '%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    CurveballLogger.logger.addHandler(handler)

CurveballLogger.init_logger()

if __name__ == '__main__':
    # This is for eyeball use only
    #
    print 'I would use logger file (%s)' % (CurveballLogger.choose_filename(),)


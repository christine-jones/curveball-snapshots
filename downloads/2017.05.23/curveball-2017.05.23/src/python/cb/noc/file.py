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
Canonical names for sentinel and bloom filter files for a given time
"""

import datetime
import os
import re
import time

SENTINEL_SUFFIX = 'sent'
SENTINEL_BF_SUFFIX = 'sbf'
BDH_SUFFIX = 'bdh'
DHEXP_SUFFIX = 'dhexp'

MAX_GENERATION = 0xffffffff

UTC_RE = '20[1-9][0-9][01][0-9][0-3][0-9]-[012][0-9][0-5][0-9]z'
SENTINEL_RE = 'cb-' + UTC_RE + '\.' + SENTINEL_SUFFIX
DHEXP_RE = 'cb-' + UTC_RE + '\.' + DHEXP_SUFFIX
SENTINEL_BF_RE = 'cb-' + UTC_RE + '-g[0-9a-fA-F]{8}\.' + SENTINEL_BF_SUFFIX
BDH_RE = 'cb-g[0-9a-fA-F]{8}\.' + BDH_SUFFIX

# FIXME: be backwards-compatible for a while.  this should be removed,
# and the pattern above should be used instead
#
SENTINEL_BF_RE = 'cb-' + UTC_RE + '-[g0-9a-fA-F]{1,9}\.' + SENTINEL_BF_SUFFIX


def date_label_str(utc=None):
    """
    Create the 'time-based label' for files that contain the
    time-based sentinels.

    Note that time resolution is assumed to be hours, so
    we always leave the minutes as '00', ignoring their real
    value.

    If utc is None, then the current UTC is used.
    """

    if utc == None:
        utc = datetime.datetime.utcnow()

    return utc.strftime('%Y%m%d-%H00z')

def generation_label_str(generation=None):
    """
    Create the 'time-based generation' string for file names that
    include a generation number.

    The generation number is when the file was created, which is often
    NOT when the file becomes active.  For files that become active at
    specific times, see data_label_str().  Some filenames include both.

    If the generation is not None nor an int, a TypeError is raised.

    If the generation is an int greater than MAX_GENERATION, or less than 0,
    then a ValueError is raised.
    """

    if generation == None:
        generation = int(time.time())

    if type(generation) != int:
        raise TypeError('generation must be an int (not %s)' %
                str(type(generation)))

    if generation < 0:
        raise ValueError('generation (%d) too small (< 0)' % generation)

    if generation > MAX_GENERATION:
        raise ValueError('generation (%d) too large (> %d)' %
                (generation, MAX_GENERATION))

    return 'g%8.x' % generation

def sentinel_fname(utc=None):
    """
    Create the name of the file for the sentinels for the given utc.
    If utc is not given, use the current time.
    """

    return 'cb-%s.%s' % (date_label_str(utc), SENTINEL_SUFFIX)

def dhexp_fname(utc=None):
    """
    Create the name of the file for the Diffie-Hellman exponents
    for the given utc.  If utc is not given, use the current time.
    """

    return 'cb-%s.%s' % (date_label_str(utc), DHEXP_SUFFIX)

def sentinel_bf_name(utc=None, generation=None):
    """
    Create the name of the file containing the Bloom filter for the sentinels
    active at the given utc, with the given generation number.

    If utc is not given, date_label_str will use the current time.

    If the generation number is None, then use the current time as the
    generation number.  Otherwise, use the given generation number.
    """

    label = date_label_str(utc)
    gen_label = generation_label_str(generation)

    return 'cb-%s-%s.%s' % (label, gen_label, SENTINEL_BF_SUFFIX)

def bdh_name(generation=None):
    """
    Create the name of a file containing a decoy host blacklist, with
    the given generation number.  If the generation number is None,
    then a new generation number is chosen.
    """

    return 'cb-%s.%s' % (
            generation_label_str(generation=generation), BDH_SUFFIX)


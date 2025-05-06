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
Utilities related to the cbchooser that do not require
importing the rest of the trawler infrastructure.
"""

import re
import urlparse

def parse_dump(fname, permitted_status=['Y'], host_only=False):
    """
    Parse a dump file of the form created by CbChooser.dump_map().

    Return a list of URLs that were probed and returned any of
    the given permitted_statuses.  By default the permitted
    statuses are just "Y", which results in a list of URLs
    that should successfully probe again.

    If host_only is true, then just the hostnames of viable decoy hosts
    are returned.
    """

    fin = open(fname, 'r')

    rows = [ line.split() for line in fin.readlines()
            if line.strip() != '' and not re.match('#', line.strip()) ]

    permitted_urls = [ row[2] for row in rows
            if (row[1] in permitted_status) and (row[2] != '<ANY>') ]

    if host_only:
        hosts = set()

        for url in permitted_urls:
            parsed = urlparse.urlparse(url)
            hosts.add('%s' % (parsed.hostname,))

        return list(hosts)
    else:
        return permitted_urls

def parse_simple_dump(fname, host_only=False):
    """
    Parse a "simple" dump file that only consists of the host, port,
    and protocol to use for each decoy proxy, and return a list of
    hosts (if host_only is non-False) or a list of (host, port, protocol)
    tuples.

    The format of each non-blank, non-comment line in the file
    is a triple of "host port protocol" (unless host_only is non-False,
    in which case it can contain only the host column).  The valid values
    for protocol are 'http' and 'https'.

    Note that the returned list may contain duplicates.  This is intentional.
    """

    permitted_protocols = [ 'http', 'https' ]

    fin = open(fname, 'r')

    rows = [ line.split() for line in fin.readlines()
            if line.strip() != '' and not re.match('#', line.strip()) ]

    fin.close()

    if host_only:
        return [ row[0] for row in rows ]
    else:
        return [ (row[0], int(row[1]), row[2]) for row in rows
                if row[2] in permitted_protocols ]


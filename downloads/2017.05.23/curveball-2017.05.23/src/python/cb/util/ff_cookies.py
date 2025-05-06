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

import glob
import os
import sqlite3

import cb.util.cb_constants

class FirefoxCookies(object):
    """
    Simple access to the domainname -> cookienames known to the local
    cookies.sqlite database (used by Firefox and variants).
    """

    def __init__(self, path=None,
            default_cookie_name=cb.util.cb_constants.COOKIE_NAME):

        if not path:
            globpath = os.path.join(os.path.expanduser('~'),
                    '.mozilla', 'firefox', '*', 'cookies.sqlite')

            matches = glob.glob(globpath)
            if not matches:
                raise ValueError('cannot find cookie file')

            path = matches[0]

        self.conn = sqlite3.connect('%s' % path)
        self.default_cookie_name = default_cookie_name

        self.refresh()

    def refresh(self):
        """
        Refresh the mapping by scanning the database.

        Should be called periodically to pick up changes as they occur.
        """

        self.cookies = dict()

        cursor = self.conn.cursor()
        query = 'SELECT baseDomain, name from moz_cookies ORDER BY id'
        cursor.execute(query)

        for (base_domain, cookie_name) in cursor.fetchall():
            ascii_cookie = cookie_name.encode('ascii', 'ignore')
            ascii_domain = base_domain.encode('ascii', 'ignore')

            if not ascii_domain in self.cookies:
                self.cookies[ascii_domain] = list()
            self.cookies[ascii_domain].append(ascii_cookie)

    def __getitem__(self, key):
        """
        If there's an entry for the given domainname, then use it.
        Otherwise, use the default cookie name (from cb_constants)
        """

        try:
            return self.cookies[key]
        except KeyError:
            return self.default_cookie_name

if __name__ == '__main__':

    def test_main():
        cookies = FirefoxCookies()

        print cookies['public-spectacle.com']
        print cookies['wikipedia.org']

    test_main()

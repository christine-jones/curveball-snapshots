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

import base64
import binascii
import cStringIO
import gzip
import os
import random
import re
import ssl
import string
import StringIO
import sys
import time
import zlib

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cb_constants as const
from M2Crypto import RSA, BIO, EVP



def get_header(header, pkt):
    """
    Extract the header field from pkt
    """
    try:
        str_pkt = str(pkt)

        init_header  = str_pkt.index( header )
        after_header = str_pkt[ ( init_header + len(header) ) : ]
        end_header   = after_header.index(const.END_LINE)

        val = after_header[ : end_header ]

    except ValueError:
        val = '-1'

    return val


def get_request_uri(header):
    """
    Extract and return the value of the GET URI from a request header.

    If the request is not a GET, or if the URI is incomplete,
    or detectably bogus, return None.
    """

    match = re.match('^GET /([^\s]*) HTTP/1.[10]\s*$', header, re.MULTILINE)
    if match:
        return match.group(1)
    else:
        return None

def get_header_value(field_name, header):
    """
    Extract the value of the given field_name from the header,
    or return '-1' if it is absent or malformed
    """

    # print 'field_name [%s] header [%s]' % (field_name, header)

    # Make sure we are only looking at the header,
    # even if the caller passes us the entire message.
    #
    pieces = header.split('\r\n\r\n', 1)
    header = pieces[0]

    match = re.search('^%s\s*:\s*([^\s]+)\s*$' % field_name, header,
            re.MULTILINE | re.IGNORECASE)

    if match:
        return match.group(1).strip()
    else:
        return '-1'


def create_http_req(self, data, ID, tunnel_type, host_name):
    """
    Create an http request.
    """

    get = 'GET /' + data.encode("hex") + ' HTTP/1.1' + const.END_LINE
    host = 'Host: ' + host_name + const.END_LINE
    user_agent = ( 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_1) ' +
                   'AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11' +
                   const.END_LINE )
    #accept = 'Accept: */*' + const.END_LINE
    accept = 'Accept: text/html,application/xhtml+xml,application/xml' + const.END_LINE
    accept_language = 'Accept-Language: en-us,en;q=0.5' + const.END_LINE
    accept_encoding = 'Accept-Encoding: gzip,deflate' + const.END_LINE
    accept_charset = 'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7' + const.END_LINE
    #keep_alive = 'Keep-Alive: 115' + const.END_LINE
    keep_alive = ''
    connection = 'Connection: keep-alive' + const.END_LINE
    referer = 'Referer: ' + const.END_LINE
    cookie = ( 'Cookie: ' + const.COOKIE_NAME + '=' + ID + '; ' +
               const.TUNNEL_COOKIE_NAME + '=' + tunnel_type + const.END_LINE )

    req = ( get +
            host +
            user_agent +
            accept +
            accept_language +
            accept_encoding +
            accept_charset +
            keep_alive +
            connection +
            referer +
            cookie +
            const.END_LINE )

    return req


def extract_http_req(self, buf):
    """
    Pull http request out of buffer
    """
    try:
        end_of_req = buf.index(const.END_HEADER) + len(const.END_HEADER)
        req = buf[:end_of_req]
        return (buf[end_of_req:], req)

    except ValueError:
        return (buf, None)


def extract_http_resp( buf, tunnel_type ):
    """
    Read an http response from the buffer and return
    the tuple (header, body).
    """
    match = re.match('HTTP/1.[01] ([0-9]{3}) ', buf)
    if not match:
        # print 'warning: BUF DOES NOT MATCH expected header [%s]' % str(buf)
        return (buf, None, '', '', -3)
    else:
        status = int(match.group(1))

    pieces = buf.split('\r\n\r\n', 1)
    if len(pieces) != 2:
        #print 'ERROR: bogus http response (%d pieces)' % len(pieces)
        return (buf, None, '', '', -4)

    header = pieces[0]

    # 301: moved permanently
    # 302: moved temporarily/"found"
    #
    if (status == 301) or (status == 302): # Look elsewhere
        match = re.search('^[Ll]ocation:\s*([^\r]*)\s$',
                header, re.MULTILINE)
        if match:
            location = match.group(1).strip()
            # print "REDIRECT LOCATION = [%s]" % location

    # search the header for either a Content-Length or Transfer-Encoding
    # tag, and use it to figure out how long the body is.
    #
    # An HTTP/1.1 header should have one or the other.
    if re.search('^[Cc]onnection:\s*[Cc]lose\s*$',
            header, re.MULTILINE):
        status = '-2'

    match = re.search('^[Cc]ontent-[Ll]ength:\s*([0-9]+)\s*$',
            buf, re.MULTILINE)
    if match:
        unzip_body = ''

        try:
            len_header = buf.index( const.END_HEADER ) + len( const.END_HEADER )
        except ValueError:
            return ( buf, None, '', '', -1)

        content_len = int( match.group(1) )
        (new_buf, response, body) = process_content_len(buf, content_len)

        if response == None:
            return (new_buf, None, '', '', -1)

        # We only unzip for http uni tunnel. The http bi tunnel
        # directly modifies the zipped payload
        #
        if re.search('^[Cc]ontent-[Ee]ncoding:\s*[Gg]zip\s*$',
                     header, re.MULTILINE) and tunnel_type is const.HTTP_UNI_TUNNEL:
            try:
                strobj = body
                fileobj = cStringIO.StringIO(strobj)
                unzip_body = gzip.GzipFile("dummy-name", 'rb', 9, fileobj).read()

            except zlib.error:
                print 'Error: response body is not gzip'

        return (new_buf, response, body, unzip_body, status)


    elif re.search('^[Tt]ransfer-[Ee]ncoding:\s*chunked\s*$',
            header, re.MULTILINE):

        finished = False
        response = None
        body = ''
        unzip_body = ''

        try:
            len_header = buf.index( const.END_HEADER ) + len( const.END_HEADER )
        except ValueError:
            return ( buf, response, body, unzip_body, status )

        new_buf = buf[len_header:]
        msg_len = len_header

        while True:
            try:
                new_line = new_buf.index( const.END_LINE )

                clen = 0
                for i in range(0,new_line):
                    digit = new_buf[i]
                    if re.match('[0-9a-fA-F]', digit):
                        clen *= 16
                        clen += int(digit, 16)

                if clen == 0:
                    finished = True
                    msg = buf[ : msg_len]
                    body = buf[len_header : msg_len]

                    # peel off the last 0\r\n\r\n.
                    new_buf = new_buf[5:] # TODO: this is a big assumption
                    break
                else:
                    chunk_offset = (
                            new_line + len(const.END_LINE) + clen + len(const.END_LINE) )

                    start_chunk = new_line + len(const.END_LINE)
                    end_chunk = start_chunk + clen #+ len(const.END_LINE)
                    chunk = new_buf[start_chunk:end_chunk]

                    unzip_body = unzip_body + chunk
                    new_buf = new_buf[ chunk_offset : ]
                    msg_len += chunk_offset

            except ValueError:
                return ( buf, None, None, None, -1 )

        if finished == True:


            # We only unzip for http uni tunnel. The http bi tunnel
            # directly modifies the zipped payload
            #
            if re.search('^[Cc]ontent-[Ee]ncoding:\s*[Gg]zip\s*$',
                    header, re.MULTILINE) and tunnel_type is const.HTTP_UNI_TUNNEL:
                try:
                    strobj = unzip_body
                    fileobj = cStringIO.StringIO(strobj)
                    unzip_body = gzip.GzipFile("dummy-name", 'rb', 9, fileobj).read()
                except zlib.error:
                    print 'Error: response body is not gzip'

            return (new_buf, msg, body, unzip_body, status)
    else:
        return(buf, None, None, None, -1 )



def process_content_len(buf, content_len):
    """
    Determine length of response header + content length
    """
    try:
        end_resp = buf.index( const.END_HEADER ) + len( const.END_HEADER )
        resp_len = end_resp + content_len

        if len( buf ) < resp_len:
            return ( buf, None, None )

    except ValueError:
        print "Buf doesn't contain full response yet"
        return ( buf, None, None )


    # Pull out response
    #
    resp    = buf[ : end_resp + content_len ]
    new_buf = buf[ end_resp + content_len : ]
    payload = buf[ end_resp : end_resp + content_len ]
    if ( new_buf == None ):
        new_buf = ''

    return (new_buf, resp, payload)





if __name__ == '__main__':
    pass

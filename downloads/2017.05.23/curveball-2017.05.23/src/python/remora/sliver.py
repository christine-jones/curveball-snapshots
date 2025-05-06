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
Implements the "sliver" heuristic for identifying plausible
decoys within a burst of connections created by local apps
"""

import errno
import pickle
import re
import socket
import struct
import sys

from twisted.internet import error
from twisted.internet import reactor

from remora.packet_sniffer import PacketSniffer

class RemoraDetectorSliver(object):
    """
    The Remora detector for the "Sliver" heuristic.

    The Remora detector sniffs, using pcapy, for outgoing TCP SYN packets
    that signal the start of new HTTP/HTTPS connections that might be to
    potential Curveball decoys.

    TODO: I don't think it checks whether the connections actually get
    created.  It would be ideal if it did, so we don't think a bogus
    or unpresponsive host would make a good decoy.
    """

    PCAP_FILTER = '((tcp[tcpflags] & tcp-syn) != 0) and \
                    (dst port 80 || dst port 443)'

    # The default sliver has a maximum length of 12 flowkeys, a minumum
    # length of 4 flowkeys, and maximum duration of 1.5 seconds
    #
    RD_SLIVER_MAX_LEN = 12
    RD_SLIVER_MIN_LEN = 4
    RD_SLIVER_MAX_DUR = 1.5

    # We don't keep history forever; we prune aggressively so that
    # we never need to remember at most RD_HISTORY_MAX_LEN flows or
    # RD_HISTORY_MAX_DUR seconds worth of events
    #
    RD_HISTORY_MAX_LEN = 50
    RD_HISTORY_MAX_DUR = 4

    # If we haven't seen a new flow in RD_IDLE_MIN_DUR seconds, then
    # assume that the system is idle and the next flow we see might
    # start a new chain of flows
    #
    RD_IDLE_MIN_DUR = 1.0

    def __init__(self, server, interface, mac_addr, addr2host):
        self.server = server
        self.interface = interface
        self.mac_addr = mac_addr
        self.addr2host = addr2host

        self.pcap_filter = self.PCAP_FILTER
        self.pcap_filter += ' and ether src ' + self.mac_addr

        # decoys that never work
        self.blacklist_filename = None
        self.suffix_blacklist = []

        # decoys that "always" work
        self.whitelist_filename = None
        self.name_whitelist = []
        self.suffix_whitelist = []

        # file used to load and save state
        self.state_filename = None

        # history of observed flow clusters
        self.flow_clusters = dict()

        self.recent_history = list()

        # start sniffing packets
        reactor.callInThread(self.start_packet_sniffer)

    def start_packet_sniffer(self):
        try:
            sniffer = PacketSniffer(self.interface, self.incoming_pkt)
        except:
            return

        sniffer.set_filter(self.PCAP_FILTER)
        sniffer.recv()

    def incoming_pkt(self, timestamp, pkt):
        reactor.callFromThread(self.pkt_handler, timestamp, pkt)

    def prune_history(self, now):
        """
        Prune any part of recent history that isn't
        recent enough any more, and never keep more than
        a certain amount of history (even when the system
        becomes very busy).

        As we dequeue items from history, we train on each
        item as a precursor for a sliver-sized prefix of the
        remainder of the history.

        TODO: the age-out interval (RD_HISTORY_MAX_DUR) and
        "certain amount" of history (RD_HISTORY_MAX_LEN)
        should be parameters.
        """

        hist_len = len(self.recent_history)

        # if the history is empty, then ind won't get set,
        # so always set it to zero to handle this edge case
        #
        ind = 0
        for ind in xrange(hist_len):
            (flowkey, tstamp) = self.recent_history[ind]

            if (now - tstamp) < self.RD_HISTORY_MAX_DUR:
                break

        # After we've gotten rid of everything too old, are
        # there still too many items?  If so, prepare to chop
        # even more, moving ind down until RD_HISTORY_MAX_LEN
        # items remain
        #
        if (hist_len - ind) > self.RD_HISTORY_MAX_LEN:
            aged_out = hist_len - self.RD_HISTORY_MAX_LEN
        else:
            aged_out = ind

        for ind in xrange(aged_out):
            (flowkey, flowtime) = self.recent_history[ind]

            sliver_start = ind + 1
            sliver_end = sliver_start + 1 + self.RD_SLIVER_MAX_LEN
            sliver = self.recent_history[sliver_start:sliver_end]

            self.add_sliver(flowkey, flowtime, sliver)

        # Now that we've trained on the aged_out prefix of
        # recent_history, remove the aged_out portion

        self.recent_history = self.recent_history[aged_out:]

        return

    def is_idle(self, now):
        """
        We consider ourselves idle if our "recent history" is
        empty or the most recent entry in our recent history is
        older than RD_IDLE_MIN_DUR seconds

        As a special case, when the system is initialized, it
        should be treated as starting/busy rather than idle,
        to avoid special cases if the Remora server starts
        during the middle of a clump. TODO we don't do that
        right now.
        """

        if len(self.recent_history) == 0:
            return True
        elif (now - self.recent_history[-1][1]) > self.RD_IDLE_MIN_DUR:
            return True
        else:
            return False

    def add_sliver(self, flowkey, flowtime, sliver):

        # print 'add_sliver: flowkey %s flowtime %f sliver %s' % (
        #         str(flowkey), flowtime, str(sliver))

        # If the sliver has elements it should have (if it's too long,
        # or contains elements that are too old) then prune them
        #
        sliver = sliver[-self.RD_SLIVER_MAX_LEN:]
        sliver = [ (key, tstamp) for (key, tstamp) in sliver
                if (tstamp - flowtime) < self.RD_SLIVER_MAX_DUR]

        # If the remaining sliver is too short, then ignore it
        #
        if len(sliver) <= self.RD_SLIVER_MIN_LEN:
            # print 'Bailing out - sliver too short'
            return

        # print 'add_sliver remaining: flowkey %s time %f sliver %s' % (
        #         str(flowkey), flowtime, str(sliver))

        # FIXME: this begins immediately with a degenerate
        # model, instead of waiting for the model to converge
        # (even in the slightest) before being ready to make
        # predictions.  It's probably very wrong at first
        #
        if not flowkey in self.flow_clusters:
            self.flow_clusters[flowkey] = dict()

        biases = self.flow_clusters[flowkey]

        for elem in sliver:
            addr = elem[0]
            if not addr in biases:
                biases[addr] = 0

            # TODO
            # It would be handy to cache the hostnames here,
            # while the DNS lookups are still fresh (in case
            # we get a later lookup that associates a different
            # name with the same ip address)

            biases[addr] += 1

    def pick_decoy(self, flowkey):

        if not flowkey in self.flow_clusters:
            return None

        biases = self.flow_clusters[flowkey]

        addrs = list()
        cntsum = 0
        for addr in biases:
            cntsum += biases[addr]
            addrs.append(addr)

        if len(addrs) == 0:
            return None

        addrs.sort(key=lambda addr: biases[addr])
        addrs.reverse()

        if 0: # diagnostics only
            for addr in addrs:
                (decoy_addr, decoy_port) = self.extract_decoy(addr)
                if decoy_addr in self.addr2host:
                    print '++ considering %s:%d' % (
                            self.addr2host[decoy_addr][0], decoy_port)
                else:
                    print '++ could consider %s:%d' % (decoy_addr, decoy_port)

        # This is a bunch of heuristics.  Should be learned,
        # but now it's futzed with by hand.
        #
        cand_names = list()
        for addr in addrs:
            (decoy_addr, decoy_port) = self.extract_decoy(addr)

            try:
                # print 'considering %s' % str(addr)
                decoy_name = self.addr2host[decoy_addr][0]
                cand_names.append(decoy_name)

                sig = '%s:%d' % (decoy_name, decoy_port)

                # print 'Candidate %s %s %d' % (str(addr), sig, biases[addr])

                if sig in self.name_whitelist:
                    # print 'picking [%s] based on whitelist' % sig
                    return addr

                for suffix in self.suffix_whitelist:
                    # print '>>> sig %s suffix %s' % (sig, suffix)
                    if sig.endswith(suffix):
                        # print 'picking [%s] based on domain' % sig
                        return addr

            except BaseException, exc:
                # print 'missing name for %s' % decoy_addr
                pass

        # print str(self.addr2host)

        for addr in addrs:
            (decoy_addr, decoy_port) = self.extract_decoy(addr)

            try:
                decoy_name = self.addr2host[decoy_addr][0]
            except BaseException, exc:
                # print 'NAMELESS HOST detected %s' % str(decoy_addr)
                # print self.addr2host
                continue

            bad_name = False
            for suff in self.suffix_blacklist:
                if decoy_name.endswith(suff):
                    # print 'blacklisted suffix %s' % suff
                    bad_name = True
                    break

            if not bad_name:
                # sig = '%s:%d' % (decoy_name, decoy_port)
                # print 'picking [%s] based on access frequency' % sig
                return addr

        # print 'No decoy chosen'
        return None

    def pkt_handler(self, timestamp, pkt):

        # convert time tuple ([sec,microsec]) to single float value
        (sec, microsec) = timestamp
        pkt_ts = sec + (microsec / 1e6)

        # parse the packet and extract a unique flow key
        flowkey = self.extract_flowkey(pkt)
        if flowkey == None:
            return

        # print 'Prepruned %s' % str(self.recent_history)
        self.prune_history(pkt_ts)
        # print 'PRUNED %s' % str(self.recent_history)

        # If we're idle, and a flow appears,
        # then see if we can predict the future based
        # on our current model and send it to the client
        # (if any)
        #
        if self.is_idle(pkt_ts):
            # print 'Detected idle period'
            decoy_flowkey = self.pick_decoy(flowkey)
            if decoy_flowkey:
                # print 'decoy_flowkey %s' % str(decoy_flowkey)

                # determine decoy host to report, and notify
                # a waiting client (if any)
                #
                (decoy_addr, decoy_port) = self.extract_decoy(decoy_flowkey)
                self.server.flow_cluster_detected(decoy_addr, decoy_port)

        # Update history
        #
        # We can't do this until after we do the is_idle check,
        # because otherwise we'll think that the most recent activity
        # is this packet itself.
        #
        self.recent_history.append((flowkey, pkt_ts))

        return

    def extract_flowkey(self, pkt):

        eth_len = 14
        if len(pkt) < eth_len:
            print >> sys.stderr, ("packet does not include ethernet header")
            return None

        eth_header = struct.unpack('!6s6sH', pkt[0:eth_len])
        if eth_header[2] != 0x800:
            print >> sys.stderr, ("invalid ethernet protocol")
            return None

        ip_len = 20
        if len(pkt) < (eth_len + ip_len):
            print >> sys.stderr, ("packet does not include ip header")
            return None

        ip_header = struct.unpack('!BBHHHBBH4s4s',
                pkt[eth_len:(eth_len + ip_len)])

        ihl = ip_header[0] & 0xF
        ip_len = ihl * 4

        protocol = ip_header[6]
        if protocol != 6:
            print >> sys.stderr, ("packet is not tcp")
            return None

        tcp_len = 20
        if len(pkt) < (eth_len + ip_len + tcp_len):
            print >> sys.stderr, ("packet does not include tcp header")
            return None

        tcp_header = struct.unpack('!HHLLBBHHH',
                pkt[(eth_len + ip_len):(eth_len + ip_len + tcp_len)])

        # print 'PKT syn %s fin %s ack %s' % (
        #         str((tcp_header[5] & 0x2) and True),
        #         str((tcp_header[5] & 0x1) and True),
        #         str((tcp_header[5] & 0x10) and True))

        daddr = socket.inet_ntoa(ip_header[9])
        dport = tcp_header[1]

        flowkey = '%s-%s' % (daddr, dport)
        return flowkey

    def extract_decoy(self, flowkey):
        (daddr, dport) = flowkey.split('-')

        return (daddr, int(dport))

    def load_whitelist(self, filename):
        self.whitelist_filename = filename

        # open whitelist file and read in by line
        try:
            fin = open(self.whitelist_filename, 'r')
            lines = fin.readlines()
            fin.close()

        except IOError, exc:
            if exc.errno == errno.ENOENT:
                print 'WARNING: whitelist file [%s] not found' % (
                        self.whitelist_filename)
            else:
                print 'ERROR: whitelist file [%s] cannot be opened' % (
                        self.whitelist_filename)
            return
        except BaseException, exc:
            print 'ERROR: unable to load whitelist file [%s]: %s' % (
                    self.whitelist_filename, str(exc))
            return

        name_whitelist = True
        whitelist = self.name_whitelist

        for line in lines:
            # skip comments
            if re.match('\s*#.*$', line):
                continue

            # blank line
            if re.match('\s*$', line):
                if name_whitelist:
                    # switch from name to suffix whitelist
                    whitelist = self.suffix_whitelist
                    name_whitelist = False
                    continue
                else:
                    break

            # remove leading/trailing whitespace
            line = line.strip()

            # only single decoy string permitted per line
            words = line.split()
            if len(words) != 1:
                print 'invalid line in whitelist \'%s\'' % line
                continue

            # add decoy to whitelist
            whitelist.append(line)

    def save_whitelist(self):
        if self.whitelist_filename == None:
            return

        try:
            fout = open(self.whitelist_filename, 'w')

        except BaseException, exc:
            print 'ERROR: unable to save whitelist: %s' % str(exc)
            return

        fout.write('# name (decoy:port) whitelist\n')
        for decoy in self.name_whitelist:
            fout.write(decoy)
            fout.write('\n')

        fout.write('\n')
        fout.write('# suffix (decoy-domain:port) whitelist\n')
        for decoy in self.suffix_whitelist:
            fout.write(decoy)
            fout.write('\n')

        fout.close()

    def load_blacklist(self, filename):
        self.blacklist_filename = filename

        # open blacklist file and read in by line
        try:
            fin = open(self.blacklist_filename, 'r')
            lines = fin.readlines()
            fin.close()

        except IOError, exc:
            if exc.errno == errno.ENOENT:
                print 'WARNING: blacklist file [%s] not found' % (
                        self.blacklist_filename)
            else:
                print 'ERROR: blacklist file [%s] cannot be opened' % (
                        self.blacklist_filename)
            return
        except BaseException, exc:
            print 'ERROR: unable to load blacklist file [%s]: %s' % (
                    self.blacklist_filename, str(exc))
            return

        for line in lines:
            # skip comments
            if re.match('\s*#.*$', line):
                continue

            # skip blank lines
            if re.match('\s*$', line):
                continue

            # remove leading/trailing whitespace
            line = line.strip()

            # only single decoy string permitted per line
            words = line.split()
            if len(words) != 1:
                print 'invalid line in blacklist \'%s\'' % line
                continue

            # add decoy to blacklist
            self.suffix_blacklist.append(line)

    def save_blacklist(self):
        if self.blacklist_filename == None:
            return

        try:
            fout = open(self.blacklist_filename, 'w')

        except BaseException, exc:
            print 'ERROR: unable to save blacklist: %s' % str(exc)
            return

        for decoy in self.suffix_blacklist:
            fout.write(decoy)
            fout.write('\n')

        fout.close()

    def load_state(self, filename):
        self.state_filename = filename

        try:
            self.flow_clusters = pickle.load(open(self.state_filename, "rb"))

        except IOError, exc:
            if exc.errno == errno.ENOENT:
                print 'WARNING: no remora state found'
            else:
                print 'ERROR: unable to load state: %s' % str(exc)
        except BaseException, exc:
            print 'ERROR: unable to load state: %s' % str(exc)

    def save_state(self):
        if self.state_filename == None:
            return

        try:
            pickle.dump(self.flow_clusters, open(self.state_filename, "wb"))

        except BaseException, exc:
            print 'ERROR: unable to load state: %s' % str(exc)
            return

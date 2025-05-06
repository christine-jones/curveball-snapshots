/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 *
 * Copyright 2014 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef CURVEBALL_SOCKETTEST_HH
#define CURVEBALL_SOCKETTEST_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS


class SocketTest : public Element {
  public:

    SocketTest();
    ~SocketTest();

    const char *class_name() const { return "SocketTest"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }
    int		configure_phase() const { return CONFIGURE_PHASE_INFO; }

    int  configure(Vector<String> &, ErrorHandler *);
    int  initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    void push(int port, Packet *p);

    void selected(int fd, int mask);

  private:

    void load_sentinels();

    int _fd;		// socket descriptor
    int _active;	// connection descriptor

    String _pathname;

    bool _load_sentinels;
};

CLICK_ENDDECLS
#endif

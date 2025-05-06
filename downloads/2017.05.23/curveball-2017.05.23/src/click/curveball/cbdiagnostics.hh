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

#ifndef CURVEBALL_CBDIAGNOSTICS_HH
#define CURVEBALL_CBDIAGNOSTICS_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS


class DeviceEntry {
  public:

    DeviceEntry():
        _element(NULL), _total_drops(0) {}
    DeviceEntry(const String & name, Element * element):
        _name(name), _element(element), _total_drops(0) {}
    ~DeviceEntry() {}

    const String & name() const { return _name; }
    Element * element()	const { return _element; }
    unsigned int drops() const { return _total_drops; }

    void update_drops(unsigned int drops) { _total_drops = drops; }

  private:

    String		_name;
    Element *		_element;
    unsigned int	_total_drops;
};


class CBDiagnostics : public Element { public:

    CBDiagnostics();
    ~CBDiagnostics();

    const char *class_name() const	{ return "CBDiagnostics"; }
    const char *port_count() const	{ return "0/0"; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    // process any configured timers that have fired
    void run_timer(Timer *timer);

  private:

    Timer 		_drop_timer;
    uint32_t		_drop_interval;

    Vector<DeviceEntry>	_devices;
};

CLICK_ENDDECLS
#endif

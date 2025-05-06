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

#include <click/config.h>
#include "cbdiagnostics.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/string.hh>
#include <click/vector.hh>
CLICK_DECLS


CBDiagnostics::CBDiagnostics()
    : _drop_timer(this), _drop_interval(0)
{
}

CBDiagnostics::~CBDiagnostics()
{
}

int
CBDiagnostics::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); i++) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0) {
            errh->error("CBDiagnostics::configure: unnamed conf arg");
            continue;
        }

        if (parts[0].equals("DEVICE", strlen("DEVICE"))) {
            if (parts.size() != 3) {
                errh->error("CBDiagnostics::configure: "
                            "conf arg requires keyword/name/value tuple");
                continue;
            }

            String name = parts[1];
            Element *e = cp_element(parts[2], this, errh);

            if (e != NULL) {
                _devices.push_back(DeviceEntry(name, e));
            } else {
                errh->error("CBDiagnostics::configure: invalid element");
            }

            continue;
        }

        if (parts.size() != 2) {
            errh->error("CBDiagnostics::configure: "
                        "conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DROP_INTERVAL", strlen("DROP_INTERVAL"))) {
            if (!cp_integer(parts[1], &_drop_interval)) {
                errh->error("CBDiagnostics::configure: invalid drop interval");
            }

        } else {
            errh->error("CBDiagnostics::configure: invalid keyword");
        }
    }

    return 0;
}

int
CBDiagnostics::initialize(ErrorHandler *)
{
    _drop_timer.initialize(this);
    if (_drop_interval > 0) {
        _drop_timer.reschedule_after_sec(1);
    }

    return 0;
}

void
CBDiagnostics::cleanup(CleanupStage)
{
    _drop_timer.clear();
}

void
CBDiagnostics::run_timer(Timer *timer)
{
    assert(timer = &_drop_timer);

    Router * router = this->router();

    for (Vector<DeviceEntry>::iterator device = _devices.begin();
         device != _devices.end();
         ++device) {

        const Handler *handler = router->handler(
                                     (*device).element(), "kernel_drops");
        if (handler == NULL) {
            click_chatter("CBDiagnostics::run_timer: "
                          "failed to find kernel_drops handler");
            continue;
        }
        assert(handler->readable());

        unsigned int drops = 0;
        String str_drops = handler->call_read((*device).element());

        if (str_drops == "??") {
            // kernel drops not supported
            continue;

        } else if (!cp_integer(str_drops, &drops)) {
            click_chatter("CBDiagnostics::run_timer: "
                          "invalid drop value %s for %s interface",
                          str_drops.c_str(), (*device).name().c_str());
            continue;
        }

        unsigned int total_drops = (*device).drops();
        if (drops > total_drops) {
            click_chatter("CBDiagnostics::run_timer: "
                          "%u packets dropped in previous %u sec interval "
                          "on %s interface (%u total drops)", 
                          (drops - total_drops), _drop_interval,
                          (*device).name().c_str(), drops);
            (*device).update_drops(drops);

        } else if (drops < total_drops) {
            click_chatter("CBDiagnostics::run_timer: resetting drop value "
                          "on %s interface",
                          (*device).name().c_str());
            (*device).update_drops(drops);

        } else {
            // number of drops remains the same; nothing to do
        }
    }

    _drop_timer.reschedule_after_sec(_drop_interval);
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CBDiagnostics)

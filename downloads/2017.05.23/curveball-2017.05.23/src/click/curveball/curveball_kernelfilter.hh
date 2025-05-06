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

#ifndef CLICK_KERNELFILTER_HH
#define CLICK_KERNELFILTER_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * The CurveballKernelFilter element is simply the Click KernelFilter element
 * with the following modifications.
 *
 *     1. The 'FORWARD', rather than 'INPUT', iptable is updated.
 *     2. Only packets of protocol 'tcp', rather than all packets, are
 *        dropped by iptables.
 *
 */


/*
=c

KernelFilter(FILTERSPEC, ...)

=s comm

block kernel from handling packets

=d

The KernelFilter element installs filter rules in the kernel to stop the
kernel from handling certain types of packets.  Use this in combination with
FromDevice.u to handle packets in user-level Click configurations.

KernelFilter uses iptables(1) to install filters; if your system does not
support iptables(1), KernelFilter will fail.  Normally KernelFilter uses
either /sbin/iptables or /usr/sbin/iptables.  To override this use the
IPTABLES_COMMAND keyword argument.

KernelFilter uninstalls its firewall rules when Click shuts down.  If Click
shuts down uncleanly, for instance because of a segmentation fault or 'kill
-9', then the rules will remain in place, and you'll have to remove them
yourself.

Currently only one form of FILTERSPEC is understood.

=over 8

=item 'C<drop dev DEVNAME>'

The kernel is blocked from handling any packets arriving on device DEVNAME.
However, these packets will still be visible to tcpdump(1), and to Click
elements like FromDevice.u.

=back

=a

FromDevice.u, ToDevice.u, KernelTap, ifconfig(8) */

class CurveballKernelFilter : public Element { public:

    enum ConfigurePhase {
	CONFIGURE_PHASE_FROMDEVICE = CONFIGURE_PHASE_PRIVILEGED - 1,
	CONFIGURE_PHASE_TODEVICE = CONFIGURE_PHASE_FROMDEVICE + 1,
	CONFIGURE_PHASE_KERNELFILTER = CONFIGURE_PHASE_FROMDEVICE + 1
    };

    CurveballKernelFilter();
    ~CurveballKernelFilter();

    const char *class_name() const	{ return "CurveballKernelFilter"; }
    const char *port_count() const	{ return PORTS_0_0; }
    int configure_phase() const		{ return CONFIGURE_PHASE_KERNELFILTER; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    static int device_filter(const String &devname, bool add_filter,
                             bool drop_icmp,
			     ErrorHandler *errh,
			     const String &iptables_command = String());

  private:

    Vector<String> _drop_devices;
    String _iptables_command;

    bool _drop_icmp;
};

CLICK_ENDDECLS
#endif

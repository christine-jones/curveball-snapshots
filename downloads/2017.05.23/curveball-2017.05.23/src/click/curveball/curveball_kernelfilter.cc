/*
 * kernelfilter.{cc,hh} -- element runs iptables to block kernel processing
 * Eddie Kohler
 *
 * Copyright (c) 2007 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

/*
 * Modifications to the original work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 *
 * Copyright 2014 - Raytheon BBN Technologies Corp.
 */

#include <click/config.h>
#include "curveball_kernelfilter.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/userutils.hh>
#include <unistd.h>
CLICK_DECLS

CurveballKernelFilter::CurveballKernelFilter(): _drop_icmp(true)
{
}

CurveballKernelFilter::~CurveballKernelFilter()
{
}

int
CurveballKernelFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse_remove_keywords(conf, this, errh,
			"IPTABLES_COMMAND", 0, cpString, &_iptables_command,
                        "DROP_ICMP", 0, cpBool, &_drop_icmp,
			cpEnd) < 0)
	return -1;
    String action, type, arg;
    for (int i = 0; i < conf.size(); i++) {
	if (cp_va_space_kparse(conf[i], this, errh,
			       "ACTION", cpkP+cpkM, cpWord, &action,
			       "TYPE", cpkP+cpkM, cpWord, &type,
			       "ARG", cpkP+cpkM, cpArgument, &arg,
			       cpEnd) < 0)
	    return -1;
	if (action != "drop" || type != "dev" || !arg)
	    return errh->error("arguments must follow 'drop dev DEVNAME'");
	_drop_devices.push_back(arg);
    }
    return 0;
}

int
CurveballKernelFilter::initialize(ErrorHandler *errh)
{
    // If you update this, also update the device_filter code in FromDevice.u
    int before = errh->nerrors();
    for (int i = 0; i < _drop_devices.size(); ++i)
	if (device_filter(_drop_devices[i], true, _drop_icmp, errh,
                          _iptables_command) < 0)
	    _drop_devices[i] = String();
    return before == errh->nerrors() ? 0 : -1;
}

void
CurveballKernelFilter::cleanup(CleanupStage stage)
{
    if (stage >= CLEANUP_INITIALIZED) {
	ErrorHandler *errh = ErrorHandler::default_handler();
	for (int i = _drop_devices.size() - 1; i >= 0; --i)
	    if (_drop_devices[i])
		device_filter(_drop_devices[i], false, _drop_icmp, errh);
    }
}

int
CurveballKernelFilter::device_filter(const String &devname, bool add_filter,
                            bool drop_icmp,
			    ErrorHandler *errh,
			    const String &iptables_command)
{
    int before = errh->nerrors();

    StringAccum iptables_cmd;
    if (iptables_command)
	iptables_cmd << iptables_command;
    else if (access("/sbin/iptables", X_OK) == 0)
	iptables_cmd << "/sbin/iptables";
    else if (access("/usr/sbin/iptables", X_OK) == 0)
	iptables_cmd << "/usr/sbin/iptables";
    else
	return errh->error("no %<iptables%> executable found");

    String ip_cmd = iptables_cmd.take_string();

    StringAccum tcp_cmd;
    tcp_cmd << ip_cmd.c_str()
            << " " << (add_filter ? "-A" : "-D") << " FORWARD -p tcp -i "
	    << shell_quote(devname) << " -j DROP";
    String final_tcp_cmd = tcp_cmd.take_string();
    String tcp_out = shell_command_output_string(final_tcp_cmd, "", errh);
    if (tcp_out)
	errh->error("%s: %s", final_tcp_cmd.c_str(), tcp_out.c_str());

    if (drop_icmp) {
        StringAccum icmp_cmd;
        icmp_cmd << ip_cmd.c_str()
                 << " " << (add_filter ? "-A" : "-D") << " FORWARD -p icmp -i "
                 << shell_quote(devname) << " -j DROP";
        String final_icmp_cmd = icmp_cmd.take_string();
        String icmp_out = shell_command_output_string(final_icmp_cmd, "", errh);
        if (icmp_out)
            errh->error("%s: %s", final_icmp_cmd.c_str(), icmp_out.c_str());
    }

    return errh->nerrors() == before ? 0 : -1;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CurveballKernelFilter)

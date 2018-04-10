# curveball-snapshots
Open-source snapshots of the Raytheon BBN Curveball project

## Intro

This repo contains archival copies of the releases and notes
from the Raytheon BBN Curveball project.  These were originally
posted at [curveball.nct.bbn.com](https://curveball.nct.bbn.com),
but this site may be removed in the future, because Raytheon
has announced plans to take down all externally-facing sites
in the BBN domain.  As long as that site still exists, it is
the definitive source for these objects; this is a backup.

The links to the release tarballs have been replaced with the
filenames of the tarballs, which are located in the `downloads`
directory.

The sources and documents created by BBN have an Apache 2.0 license;
materials copied or derived from third-party software are marked
with the original license.

## Original site text

**Curveball - Disguising secure communications as ordinary web traffic**

Curveball provides secure, covert communication, even to sites that
are monitored, censored, or blocked by a third party.

**SECURITY RISKS IN MONITORED ENVIRONMENTS**

Secure and timely communication is essential to situational awareness,
tactical decisions, and strategic planning. Current long-range
communication mechanisms used by US forces and their allies conducting
operations in a highly monitored environment are not adequately
secure; they can be detected, traced, or disrupted. Special-purpose
communications equipment, such as military radios, have identifiable
RF signatures that reveal their presence and location to a third
party. A stealthier way to avoid detection is to look like everyone
else's: that is, use the same commercial devices and Internet
communications infrastructure that the local population uses but
in such a way that a third party cannot detect the communication
or discover its true destination or content.

**THE CURVEBALL SOLUTION**

BBN's Curveball project, under the DARPA SAFER Warfighter Communications
program, seeks to solve the problem of secure and undetectable
communications in a monitored environment. The Curveball project
has developed software that runs on commercial smartphones and
laptops, and software that runs on routers in the network, that
disguise secure communications as ordinary web traffic. Using
Curveball, users can securely communicate with each other or their
command and control and access social intelligence sources such as
Twitter or Facebook. A third party attempting to detect or monitor
Curveball traffic sees traffic that appears to be to and from
innocuous web sites, such as game, sporting news, or e-commerce
sites.

**DECOY ROUTING**

Curveball provides security by hiding in plain sight. Curveball
uses ordinary, commodity devices over standard, widely-used protocols,
to make what appear to be connections to popular, innocuous web
sites. What really happens is that Curveball uses decoy routing to
securely disguise the true destination and content of the covert
connections. A third party can neither detect the true destination
of a Curveball connection nor intercept the data being sent over
the connection. To a network monitor, connections created by Curveball
users appear to be unremarkable connections to unremarkable web
sites.

**HOW CURVEBALL WORKS**

To create a Curveball connection, the Curveball user opens a
connection to a web site using a standard web protocol. Once
connected, the Curveball software embeds a cryptographically-secure
signal within its messages to that web site. This signal is generated
from a user's personal secret key to assure the user's authority
to use Curveball.

When the connection passes through a router on the open Internet
that is running the Curveball software, that router detects the
signal and initiates a cryptographically-secure handshake with the
Curveball user. Ordinary routers or other third parties cannot
detect or decode these signals or the handshake. When the handshake
is complete, the user can tunnel any protocol (e.g., Skype, VoIP,
VPN, HTTP, or HTTPS) through the Curveball connection and therefore
has the ability to access any web site or network resource on the
open Internet. All standard network applications can use Curveball
without modification.

**STEALTH OPERATION**

Curveball is difficult to detect or block because, unlike contemporary
circumvention systems, it does not require the user to connect to
a specific proxy site or use an unusual protocol. If a third party
can discover the location of the specific proxy service, it can
block, monitor, or, in some cases, spoof the proxy. Similarly, if
a third party blocks or monitors uncommon protocols on its network,
then protocols that cannot masquerade as common protocols will be
defeated. In contrast, Curveball cannot be blocked without blocking
the Internet itself: any route through a Curveball router makes
every site outside the monitored network accessible.

**Downloads**

**2017.05.23**

This is an experimental release that diverges from previous releases.
This implementation includes many changes to the DR in order to
make it able to handle speeds of 10Gb/s. See the README.txt in the
doc directory for more info.

`2017.05.23/curveball-2017.05.23.tgz`

`sha256sum: f0ee04a59ff74be314fa39f915b4239c5fbdd81fc63d3a4204c218f41815e2f8 *curveball-2017.05.23.tgz`

**2017.05.12** 

This release is intended to be identical to the 2016.03.08 release,
but includes updated test certificates (which should be valid until
2020). The certificates in the 2016.03.08 release expired several
months ago.

`2017.05.12/curveball-2017.05.12.tgz`

`sha256sum: 520af86116cfbac8bba62397446287aae59df306172e73f22557dca132f4b252 *curveball-2017.05.12.tgz`

**2016.03.08**

This release fixes bugs in handling ACK packets, but is otherwise
identical to the 2014.12.19 release. The release notes and instructions
for the 2014.12.19 release may be used for this release (after
replacing the release name).

`2016.03.08/curveball-2016.03.08.tgz`

`sha256sum: c62b2231da9adae83a4e4b58e6028e48ecd77a0d4b4e1130b6b17c29da0c67af *curveball-2016.03.08.tgz`

**2014.12.19**

Release notes
Source tarball 

`2014.12.19/curveball-2014.12.19.tgz`

`sha256sum: e4dc89d1f98557f486153e590be15bb5acb12e74f572e46ef2b0ddf31ab2b8ff *curveball-2014.12.19.tgz`

**2014.06.18**

`2014.06.18/curveball-2014.06.18.tgz`

`sha256sum: ccfdcdb3b435f810bbf4ff1508d52905f0d03d34eda45a94981c2801ec2d85ce *curveball-2014.06.18.tgz`

**Errata**

This section contains errata for the documents that describe how
to build, install, configure, and run BBN Curveball. The errata are
ordered by release and update date.

**2014.06.18**

No errata yet

**2014.06.18**

Updated 2014-07-07

The instructions for starting dr.py are confusing in the case of
asymmetric routes.

If the route between the client and the decoy is asymmetric with
respect to the dr node (packets from the client to the decoy traverse
the dr, but packets from the decoy to the client do not) then the
--clientname parameter must not be the name of the client. Instead,
the value of --clientname should be the name or IP address of the
router adjacent to the dr that client-to-decoy packets traverse
prior to the dr node.

For example, consider a topology where router0 sends all the
client-to-decoy packets through router2, and router3 sends all
decoy-to-client packets through router1:

```
                  +-> router2 -> dr -+
                  |                  |
    client <-> router0            router3 <-> decoy
                  |                  |
                  +<--- router1 <----+
```
    
In this case, router2 should be used as the value of the --clientname
parameter because the packets from the client arrive at the dr on
the interface adjacent to router2.

Updated 2014-06-27

The instructions for starting decoyproxy.py omitted a parameter
that is required for many installations. The default value is, in
the general case, incorrect.

The --permitted-subnet parameter is used to specify the subnet that
the decoy proxy should use for the source address of proxied packets.
The node where the decoy proxy is run must have an interface
configured on this subnet. The subnet may be specified as a complete
IP address, in which case it must be a address of the decoy proxy
node.

For example, if the decoy proxy node has three network interfaces
(one for management, and one for a connection to a DR, and one
connected to the Internet), then this is used to specify that the
latter is to be used for outbound packets.

Note that even if the node only has one configured interface, it
is still necessary to specify the --permitted-subnet. This behavior
may change in future releases.

*This document does not contain technology or technical data controlled
under either the U.S. International Traffic in Arms Regulations or
the U.S. Export Administration Regulations. E17-2W2Z*





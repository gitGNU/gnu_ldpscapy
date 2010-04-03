************
Installation
************

Requierements
=============

To use this layer, you need `Scapy <http://www.secdev.org/projects/scapy>`_.



Download
========

Get the last version of LDPScapy here:

http://git.savannah.gnu.org/cgit/ldpscapy.git/snapshot/ldpscapy-master.tar.gz


Installation
============

First, install Scapy. It will create a directory containing every class owned by scapy. Find this directory.

* On ubuntu it is: /usr/lib/pymodules/python2.6/scapy
* On gentoo it is: /usr/lib/python2.6/site-packages/scapy

The scapy directory contains a subdir named layers. Copy the file LDP.py on it.

Then edit the file config.py on the scapy dir and (at the end) on the :attr:`load_layers` add "LDP"::

    load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs", "hsrp", "inet6", "ir", "isakmp", "l2tp",
                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp",
                   "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "LDP" ]


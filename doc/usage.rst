*****
Usage
*****

LdpScapy defines somes LDP messages. This page briefly describes the fields holds by the messages.

For more information about LDP use, please read :rfc:`3036`.

LDP PDUs
========

LDP()
-----
Main LDP packet

    * :attr:`version` (short): (default 1)
    * :attr:`len` (short): Packet length, auto-calculated
    * :attr:`id` (IP): First four octets of the LDP Session identifier.
    * :attr:`space` (short): Last two octets of the LDP Session identifier.

When you create a LDP packet, the previous layer (TCP or LDP) will automatically change the sport and dport to 646 if you did'nt explicitly specified them.


::

	LDP(id="10.0.0.2",space=04)



LDPNotification()
-----------------
Notification Message

    * :attr:`len`
    * :attr:`id` (int)
    * :attr:`status` (int): status code


::

	LDP()/LDPNotification(id=0x34,status=1)



LDPHello()
----------
Hello Message

    * :attr:`len`
    * :attr:`id` (int)
    * :attr:`params`: Common Hello TLV Field, list of 3 numeric values (cf. :ref:`CommonHelloTLVField`)
    

Example::

	LDP()/LDPHello(id=0x34,params=[180,0,0])



Initialization Message
----------------------
Class to be rewritten. Please don't use it.

LDPKeepAlive()
--------------

    * :attr:`len`
    * :attr:`id`


.. _LDPAddress:

LDPAddress()
------------

    * :attr:`len`
    * :attr:`id` (int)
    * :attr:`address`: list of IP address (cf. :ref:`AddressTLVField`)

::

	LDP()/LDPAddress(address=["10.0.0.2","10.2.1.2"])



LDPAddressWM()
--------------
Address Withdraw Message


Same format as :ref:`LDPAddress`


.. _LDPLabelMM:

LDPLabelMM()
------------
Label Mapping Message

    * :attr:`len`
    * :attr:`id`
    * :attr:`fec`: list of fec tuples (cf :ref:`FecTLVField`)
    * :attr:`label` (int): Label used (cf :ref:`LabelTLVField`)

::

	LDP()/LDPLabelMM(fec=[("134.245.3.2",12),("12.4.3.2",24)],label=4)




LDPLabelReqM()
--------------
Label Request Message

    * :attr:`len`
    * :attr:`id`
    * :attr:`fec`: list of fec tuples (cf :ref:`FecTLVField`)

LDPLabelARM()
-------------
Label Abort Request Message

    * :attr:`len`
    * :attr:`id`
    * :attr:`fec`: list of fec tuples (cf :ref:`FecTLVField`)
    * :attr:`labelRMid` (int): Label used (cf :ref:`LabelTLVField`)

LDPLabelWM()
------------
Label Withdraw Message

Same format as :ref:`LDPLabelMM`


LDPLabelRelM()
--------------
Label Release Message

    * :attr:`len`
    * :attr:`fec`: List of fec tuples (cf :ref:`FecTLVField`)
    * :attr:`label`: Label used (cf :ref:`LabelTLVField`)



TLVs
====

.. _FecTLVField:

FecTLVField
-----------

List of tuples containing:

* IP address
* Mask


Example::

	[("134.245.3.2",12),("134.24.5.6",32)]


.. _LabelTLVField:

LabelTLVField
-------------

Integer representing the label.


.. _AddressTLVField:

AddressTLVField
---------------

List of IP addresses:

Example::

	["10.0.0.2","10.1.12.2"]



.. _CommonHelloTLVField:

CommonHelloTLVField
-------------------

List containing three values:

* Hold time
* Targeted Hello (1 yes, 0 no)
* Request Send Targeted Hellos (1 yes, 0 no)

Example::

	[180,0,0]



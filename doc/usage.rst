*****
Usage
*****

LdpScapy defines somes LDP messages. This page briefly describes the fields holds by the messages.

For more information about LDP use, please read :rfc:`3036`.

LDP PDUs
========

LDP()
-----------------------
Main LDP packet

    * version (short): (default 1)
    * len (short): Packet length, auto-calculated
    * id (IP): First four octets of the LDP Session identifier.
    * space (short): Last two octets of the LDP Session identifier.

When you create a LDP packet, the previous layer (TCP or LDP) will automatically change the sport and dport to 646 if you did'nt explicitly specified them.


::

	LDP(id="10.0.0.2",space=04)

::


LDPNotification()
---------------------------------------
Notification Message

    * len
    * id (int)
    * status (int): status code


::

	LDP()/LDPNotification(id=0x34,status=1)
::

LDPHello()
-------------------------
Hello Message

    * len
    * id (int)
    * params: Common Hello TLV Field, list of 3 numeric values
          * Hold time
          * Targeted Hello (1 yes, 0 no)
          * Request Send Targeted Hellos (1 yes, 0 no)

::

	LDP()/LDPHello(id=0x34,params=[180,0,0])
::

Initialization Message
----------------------
Class to be rewritten. Please don't use it.

LDPKeepAlive()
----------------------------

    * len
    * id


.. _LDPAddress:

LDPAddress()
----------

    * len
    * id (int)
    * address: list of IP address

::

	LDP()/LDPAddress(address=["10.0.0.2","10.2.1.2"])

::

LDPAddressWM()
----------------------------------------
Address Withdraw Message


Same format as :ref:`LDPAddress`


.. _LDPLabelMM:

LDPLabelMM()
-----------------------------------
Label Mapping Message

    * len
    * id
    * fec: list of fec tuples:
          * IP Address
          * mask length
    * label (int)

::

	LDP()/LDPLabelMM(fec=[("134.245.3.2",12),("12.4.3.2",24)],label=4)

::


LDPLabelReqM()
-------------------------------------
Label Request Message

    * len
    * id
    * fec: (see :ref:`LDPLabelMM` for the format)

LDPLabelARM()
------------------------------------------
Label Abort Request Message

    * len
    * id
    * fec: (see :ref:`LDPLabelMM` for the format)
    * labelRMid (int)

LDPLabelWM()
-----------------------------------
Label Release Message

Same format as :ref:`LDPLabelMM`


LDPLabelRelM()
-------------------------------------
Label Release Message

    * len
    * fec
    * label


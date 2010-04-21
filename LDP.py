# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2010 Florian Duraffourg

import struct

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP
from scapy.layers.inet import TCP
from scapy.base_classes import Net


# Guess payload
def guess_payload(p):
    LDPTypes = {
        0x0001: LDPNotification,
        0x0100: LDPHello,
        0x0200: LDPInit,
        0x0201: LDPKeepAlive,
        0x0300: LDPAddress,
        0x0301: LDPAddressWM,
        0x0400: LDPLabelMM,
        0x0401: LDPLabelReqM,
        0x0404: LDPLabelARM,
        0x0402: LDPLabelWM,
        0x0403: LDPLabelRelM,
        }
    type = struct.unpack("!H",p[0:2])[0]
    type = type & 0x7fff
    if type == 0x0001 and struct.unpack("!H",p[2:4])[0] > 20:
        return LDP
    if type in LDPTypes:
        return LDPTypes[type]
    else:
        return Raw

## Fields ##

# 3.4.1. FEC TLV

class FecTLVField(StrField):
    islist=1
    def m2i(self, pkt, x):
        nbr = struct.unpack("!H",x[2:4])[0]
        used = 0
        x=x[4:]
        list=[]
        while x:
            #if x[0] == 1:
            #   list.append('Wildcard')
            #else:
            #mask=ord(x[8*i+3])
            #add=inet_ntoa(x[8*i+4:8*i+8])
            mask=ord(x[3])
            nbroctets = mask / 8
            if mask % 8:
                nbroctets += 1
            add=inet_ntoa(x[4:4+nbroctets]+"\x00"*(4-nbroctets))
            list.append( (add, mask) )
            used += 4 + nbroctets
            x=x[4+nbroctets:]
        return list
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = "\x01\x00"
        l = 0
        fec = ""
        for o in x:
            fec += "\x02\x00\x01"
            # mask length
            fec += struct.pack("!B",o[1])
            # Prefix
            fec += inet_aton(o[0])
            l += 8
        s += struct.pack("!H",l)
        s += fec
        return s
    def size(self, s):
        """Get the size of this field"""
        l = 4 + struct.unpack("!H",s[2:4])[0]
        return l
    def getfield(self, pkt, s):
        l = self.size(s)
        return s[l:],self.m2i(pkt, s[:l])
        

# 3.4.2.1. Generic Label TLV

class LabelTLVField(StrField):
    def m2i(self, pkt, x):
        return struct.unpack("!I",x[4:8])[0]
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = "\x02\x00\x00\x04"
        s += struct.pack("!I",x)
        return s
    def size(self, s):
        """Get the size of this field"""
        l = 4 + struct.unpack("!H",s[2:4])[0]
        return l
    def getfield(self, pkt, s):
        l = self.size(s)
        return s[l:],self.m2i(pkt, s[:l])


# 3.4.3. Address List TLV

class AddressTLVField(StrField):
    islist=1
    def m2i(self, pkt, x):
        nbr = struct.unpack("!H",x[2:4])[0] - 2
        nbr /= 4
        x=x[6:]
        list=[]
        for i in range(0,nbr):
            add = x[4*i:4*i+4]
            list.append(inet_ntoa(add))
        return list
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        l=2+len(x)*4
        s = "\x01\x01"+struct.pack("!H",l)+"\x00\x01"
        for o in x:
            s += inet_aton(o)
        return s
    def size(self, s):
        """Get the size of this field"""
        l = 4 + struct.unpack("!H",s[2:4])[0]
        return l
    def getfield(self, pkt, s):
        l = self.size(s)
        return s[l:],self.m2i(pkt, s[:l])


# 3.4.6. Status TLV

class StatusTLVField(StrField):
    islist=1
    def m2i(self, pkt, x):
        l = []
        statuscode = struct.unpack("!I",x[4:8])[0]
        l.append( (statuscode & 2**31) >> 31)
        l.append( (statuscode & 2**30) >> 30)
        l.append( statuscode & 0x3FFFFFFF )
        l.append( struct.unpack("!I", x[8:12])[0] )
        l.append( struct.unpack("!H", x[12:14])[0] )
        return l
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = "\x03\x00" + struct.pack("!H",12)
        statuscode = 0
        if x[0] != 0:
            statuscode += 2**31
        if x[1] != 0:
            statuscode += 2**30
        statuscode += x[2]
        s += struct.pack("!I",statuscode)
        if len(x) > 3:
            s += struct.pack("!I",x[3])
        else:
            s += "\x00\x00\x00\x00"
        if len(x) > 4:
            s += struct.pack("!H",x[4])
        else:
            s += "\x00\x00"
        return s
    def getfield(self, pkt, s):
        l = 14
        return s[l:],self.m2i(pkt, s[:l])


# 3.5.2 Common Hello Parameters TLV
class CommonHelloTLVField(StrField):
    islist = 1
    def m2i(self, pkt, x):
        list = []
        v = struct.unpack("!H",x[4:6])[0]
        list.append(v)
        v = x[6] & 0x80
        v = v >> 7
        list.append(v)
        v = x[6] & 0x40
        v = v >> 6
        list.append(v)
        return list
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = "\x04\x00\x00\x04"
        s += struct.pack("!H",x[0])
        byte = 0
        if x[1] == 1:
            byte += 0x80
        if x[2] == 1:
            byte += 0x40
        s += struct.pack("!B",byte)
        s += "\x00"
        return s
    def getfield(self, pkt, s):
        l = 8
        return s[l:],self.m2i(pkt, s[:l])
    


## Messages ##

# 3.5.1. Notification Message
class LDPNotification(Packet):
    name = "LDPNotification"
    fields_desc = [ BitField("u",0,1),
                    BitField("type", 0x0001, 15),
                    ShortField("len", None),
                    IntField("id", 0) ,
                    StatusTLVField("status",(0,0,0,0,0)) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.2. Hello Message
class LDPHello(Packet):
    name = "LDPHello"
    fields_desc = [ BitField("u",0,1),
                    BitField("type", 0x0100, 15),
                    ShortField("len", None),
                    IntField("id", 0) ,
                    CommonHelloTLVField("params",[180,0,0]) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.3. Initialization Message
class LDPInit(Packet):
    name = "LDPInit"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0200, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    BitField("oo",0,2),
                    XBitField("parms",0x0500,14),
                    ShortField("tlen",14),
                    ShortField("version",1),
                    ShortField("keepalive",180),
                    BitField("a",0,1),
                    BitField("d",0,1),
                    BitField("reserved",0,6),
                    ByteField("pvlim",0),
                    ShortField("maxlen",0),
                    IPField("rid","127.0.0.1"),
                    ShortField("rspace",0) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.4. KeepAlive Message
class LDPKeepAlive(Packet):
    name = "LDPKeepAlive"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0201, 15),
                    ShortField("len", None),
                    IntField("id", 0)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.5. Address Message

class LDPAddress(Packet):
    name = "LDPAddress"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0300, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    AddressTLVField("address",None) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.6. Address Withdraw Message

class LDPAddressWM(Packet):
    name = "LDPAddressWM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0301, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    AddressTLVField("address",None) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.7. Label Mapping Message

class LDPLabelMM(Packet):
    name = "LDPLabelMM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0400, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    FecTLVField("fec",None),
                    LabelTLVField("label",0)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)

# 3.5.8. Label Request Message

class LDPLabelReqM(Packet):
    name = "LDPLabelReqM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0401, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    FecTLVField("fec",None)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.9. Label Abort Request Message

class LDPLabelARM(Packet):
    name = "LDPLabelARM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0404, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    FecTLVField("fec",None),
                    IntField("labelRMid",0)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.10. Label Withdraw Message

class LDPLabelWM(Packet):
    name = "LDPLabelWM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0402, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    FecTLVField("fec",None),
                    LabelTLVField("label",0)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.5.11. Label Release Message

class LDPLabelRelM(Packet):
    name = "LDPLabelRelM"
    fields_desc = [ BitField("u",0,1),
                    XBitField("type", 0x0403, 15),
                    ShortField("len", None),
                    IntField("id", 0),
                    FecTLVField("fec",None),
                    LabelTLVField("label",0)]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay  
    def guess_payload_class(self, p):
        return guess_payload(p)


# 3.1. LDP PDUs
class LDP(Packet):
    name = "LDP"
    fields_desc = [ ShortField("version",1),
                    ShortField("len", None),
                    IPField("id","127.0.0.1"),
                    ShortField("space",0) ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)+len(pay)-4
            p = p[:2]+struct.pack("!H", l)+p[4:]
        return p+pay
    def guess_payload_class(self, p):
        return guess_payload(p)

bind_layers( TCP, LDP, sport=646, dport=646 )
bind_layers( UDP, LDP, sport=646, dport=646 )

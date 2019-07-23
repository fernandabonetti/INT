
from scapy.all import *
import sys, os

TYPE_IPV4 = 0x800
TYPE_INT = 0x1212

class SwitchTrace(Packet):
    fields_desc = [ ShortField("pid", 0),
                    IntField("swid", 0),
                    IntField("qdepth", 0),
                    IntField("hop_delay", 0),
                    BitField("ingress", 0, 48)]

bind_layers(Ether, SwitchTrace, type=TYPE_INT)
bind_layers(SwitchTrace, SwitchTrace, pid=TYPE_INT)
bind_layers(SwitchTrace, IP, pid=TYPE_IPV4)

#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import json

from scapy.all import sendp, send, sniff, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField, XBitField
from scapy.packet import Packet, bind_layers
from intHeader import SwitchTrace
from time import sleep
from datetime import datetime

TYPE_INT = 0x1212

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def showPacket(pkt):
    stats = {}
    path = []
    hop_delays = []
    timestamps = []
    queue_lengths = []
    flux = 0
    hop_avg = 0
    if SwitchTrace in pkt:
        pkt.show()


def main():
    #archivename = "data/"+sys.argv[1]
    iface = get_if()
    print("Interface: %s" % iface)
    sniff(iface = iface, prn = lambda x: showPacket(x))

if __name__ == '__main__':
    main()

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, sniff, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField, XBitField
from scapy.packet import Packet, bind_layers
from intHeader import SwitchTrace

TYPE_INT = 0x1212

from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def showPacket(pkt):
    if SwitchTrace in pkt:
	print "oi"
        pkt.show2()

def main():

    iface = 'h2-eth0'
    print("Interface: %s" % iface)
    sniff(iface = iface, prn = lambda x: showPacket(x))

if __name__ == '__main__':
    main()

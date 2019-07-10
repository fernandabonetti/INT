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

def showPacket(pkt, archivename):
    stats = {}
    path = []
    hop_delays = []
    timestamps = []
    queue_lengths = []
    flux = 0
    hop_avg = 0
    if SwitchTrace in pkt:
        pkt.show()
        print("  Switch    Queue Len    Delay(mS)")
        for i in range(0, 6):
            hop_avg += float(pkt[SwitchTrace][i].hop_delay)
            path.append(int(pkt[SwitchTrace][i].swid))
            hop_delays.append(float(pkt[SwitchTrace][i].hop_delay))
            timestamps.append(pkt[SwitchTrace][i].ingress)
            queue_lengths.append(int(pkt[SwitchTrace][i].qdepth))
            flux = pkt[IP].tos
            print(path[i], queue_lengths[i],hop_delays[i])
        print("Delay average:", hop_avg/6)
        stats[flux] = {"hop_avg": hop_avg, "path": path, "hop_delays": hop_delays, "timestamps": timestamps, "queue_stats": queue_lengths}
        with open(archivename, 'w') as fp:
            json.dump(stats, fp,  ensure_ascii=False, sort_keys=False)


def main():
    archivename = "data/"+sys.argv[1]
    iface = get_if()
    print("Interface: %s" % iface)
    sniff(iface = iface, prn = lambda x: showPacket(x, archivename))

if __name__ == '__main__':
    main()

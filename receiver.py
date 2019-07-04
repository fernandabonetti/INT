import sys
import os

from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import IP, TCP, UDP, Raw

def showPacket(pkt):
    pkt.show()

def main():
    ifaces = list(filter(lambda i: 'enp3s0' in i, os.listdir('/sys/class/net/')))
    iface = ifaces[0]
    print("Interface: %s" % iface)
    sniff(iface = iface, prn = lambda x: showPacket(x))

if __name__ == '__main__':
    main()
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField
from scapy.packet import Packet, bind_layers
from intHeader import SwitchTrace
from time import sleep

TYPE_INT = 0x1212
TYPE_IPV4 = 0X800

def get_if():
    ifs = get_if_list()
    iface = None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv) < 2:
        print('[WARNING] Please inform 3 arguments: <destination> "<message>" <flux identifier>')
        exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument('address', type = str, help = "Address")
    parser.add_argument('message', type = str, help = "Payload Message")
    parser.add_argument('flux', type = int, default = 0, help = 'Number to identify the flux a.k.a. DSCP')
    args = parser.parse_args()

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    flux = args.flux
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type = TYPE_INT)
    pkt = pkt/SwitchTrace()/SwitchTrace()/SwitchTrace()/SwitchTrace()/SwitchTrace()/SwitchTrace()/IP(dst=addr, tos=flux)/TCP()/ args.message

    try:
      for i in range(0,1):
        sendp(pkt, iface=iface)
        pkt.show2()
        sleep(1)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()

import sys
import argparse
import socket
from scapy.fields import BitField
from scapy.packet import Packet, bind_layers


class INT(Packet):
    name = "INT" 
    fields_desc = [
        BitField("swid", 0, 32),
        BitField("protocol", 0, 16),
        BitField("queue_id", 0, 1),
        BitField("queue_length", 100, 32),
        BitField("in_timestamp", 0, 32),
        BitField("hop_delay", 0, 32)
    ]

def main():
    if len(sys.argv) < 3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    address = socket.gethostbyname(sys.argv[1])
  


if __name__ == '__main__':
    main()
import sys
import argparse
import socket
from scapy.fields import BitField
from scapy.packet import Packet, bind_layers


class INT(Packet):
    name = "INT" 
    fields_desc = [
        BitField("version", 4, 1),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1)
        BitField("rsvd1", 0, 5)
        BitField("rsvd2", 0,  5)
        BitField("hop_len", 2, 5)
        ByteField("rem_hop_cnt", 6)
        "int_mask_0003"
        "int_mask_0407"
        "int_mask_0811"
        "int_mask_1215"
        "reserved"
        "switchid"
        "queue" ] 

def main():
    if len(sys.argv) < 3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    address = socket.gethostbyname(sys.argv[1])
  


if __name__ == '__main__':
    main()
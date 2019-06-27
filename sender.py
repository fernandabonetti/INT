import sys
import argparse
import socket


class INT(Packet):
    name = "INT"
    fields_desc = [
        "version"
        "rep"
        "c"
        "e"
        "m"
        "rsvd1"
        "rsvd2"
        "hop_len"
        "rem_hop_cnt"
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
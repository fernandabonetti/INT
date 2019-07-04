import sys
import argparse
import socket
from scapy.fields import BitField
from scapy.packet import Packet, bind_layers
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP

TYPE_INT = 0x1212

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

def get_if():
	ifs=get_if_list()
	iface = None 
	for i in get_if_list():
		if "enp3s0" in i:
			iface=i
			break;
	if not iface:
		print("Cannot find eth0 interface")
		exit(1)
	return iface

def main():
	if len(sys.argv) < 3:
		print('[WARNING] Please inform 3 arguments: <destination> "<message>" <flux identifier>')
		exit(1)
	
	parser = argparse.ArgumentParser()
	parser.add_argument('ip_addr', type=str, help = "Destination IP Address")
	parser.add_argument('message', type=str, help = "Payload Message")
	parser.add_argument('flux', type = int, default=0, help='Number to identify the flux a.k.a. DSCP')
	args = parser.parse_args()
	
	address = socket.gethostbyname(sys.argv[1])
	flux = args.flux
	iface = get_if()
		
	pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_INT)
	pkt = pkt /INT(protocol=0x0800) / IP(tos=flux, dst=address) / args.message

	pkt.show()
	
if __name__ == '__main__':
	main()
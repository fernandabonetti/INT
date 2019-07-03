/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const   bit<16> TYPE_IPV4 = 0x800;
const   bit<16> TYPE_INT = 0x1212;
typedef bit<9>  egressSpec_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

//155 bits
header int_switch_t {	
	bit<32> sw_id;
	bit<16> protocol;
	bit<32> queue_id;
	bit<32> queue_length;
	bit<32> ingress_timestamp;
	bit<32> hop_delay;
}

struct headers {
	ethernet_t		ethernet;
	int_switch_t	int_header;
	ipv4_t			ipv4;
}

//Copy Metadata to clone
struct metadata {
    bit<32> sw_id;
	bit<16> protocol;
	bit<32> queue_id;
	bit<32> queue_length;
	bit<32> ingress_timestamp;
	bit<32> hop_delay;
}

error {
    BadIPv4HeaderChecksum
}

parser IngressParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT: parse_Int;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_Int {
        packet.extract(hdr.int_header);
        transition select(hdr.int_header.protocol) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control MyIngress(inout headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //verificar
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    action int_ingress(egressSpec_t port, switchID_t swid) {
		hdr.int_header.sw_id = swid;   //Add switch id to header
        standard_metadata.egress_spec = port;
    }

    table int_exact {
        actions = {
            int_ingress;
            drop;
        }
        //size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.int_header.isValid()) {
            ipv4_lpm.apply();
        }

        if (hdr.int_header.isValid()) {
            int_exact.apply();
        }
    }
}

control MyEgress(inout headers hdr,
			inout metadata meta,
			inout standard_metadata_t standard_metadata) {


	action update_timestamps(){
		hdr.int_header.ingress_timestamp = (bit<32>) standard_metadata.enq_timestamp;
		hdr.int_ingress.hop_delay = (bit <32>) standard_metadata.deq_timedelta;
	}

	action update_queue(){
		//hdr.int_header.queue_id = 
		hdr.int_header.queue_length = (bit<32>) standard_metadata.deq_qdepth;
	}			

	table update_int {
		actions = {
			update_timestamps();
			update_queue();
		}
	}			

    apply {
		if(hdr.int_header.isValid()){
			update_int.apply();
		}
	  }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      	  hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_header);
        packet.emit(hdr.ipv4);
    }
}
V1Switch(
IngressParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
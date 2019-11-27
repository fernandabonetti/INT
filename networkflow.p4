/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 7

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_INT_HEADER = 0x1212;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qdepth_t;
typedef bit<32> switchID_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header int_header_t {
	bit<16>     proto_id;
	switchID_t  hop_delay;
	bit<48>     in_timestamp;
	bit<32>  eq_timestamp;
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<8>    diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}


header tcp_t {
  bit<16> srcAddr;
  bit<16> dstAddr;
  bit<32> seqNumber;
  bit<32> ackNumber;
  bit<4> dataOffset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}

struct metadata {
	switchID_t  swid;
	qdepth_t    qdepth;
	switchID_t  hop_delay;
	bit<48>     in_timestamp;
}

struct headers {
	ethernet_t				ethernet;
	int_header_t[MAX_HOPS]	int_header;
	ipv4_t                	ipv4;
	tcp_t										tcp;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_INT_HEADER: parse_hint;
			TYPE_IPV4: parse_ipv4;
			default: accept;
		}
	}

	state parse_hint {
		packet.extract(hdr.int_header.next);
		transition select(hdr.int_header.last.proto_id) {
			TYPE_IPV4: parse_ipv4;
			TYPE_INT_HEADER : parse_hint;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			6       : parse_tcp;
			default : accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
	}

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
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
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	apply {
		if (hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
	}
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {

		action add_swtrace(switchID_t swid){
				 	hdr.int_header.push_front(1);
					hdr.int_header[0].setValid();
					hdr.int_header[0].proto_id = TYPE_INT_HEADER;
			 		hdr.int_header[0].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
			 		hdr.int_header[0].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
					hdr.int_header[0].eq_timestamp = (bit <32>) standard_metadata.enq_timestamp;
		}

	table swtrace {
		actions = {
			add_swtrace;
  		NoAction;
		}
		default_action = NoAction();
	}

	apply {
		swtrace.apply();
	}
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.int_header);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_HOPS 9


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

header tcp_hdr {
    bit<16> srcAddr;
    bit<16> dstAddr;
    bit<32> seqNumber;
    bit<32> ackNumber;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;
    bit<6> dscp;
    bit<2> rsvd2
}

header int_header_t {
    bit<4> ver;
    bit<2> rep;
    bit<1> c;
    bit<1> e;
    bit<1> m;
    bit<7> rsvd1;
    bit<3> rsvd2;
    bit<5> hop_metadata_len;
    bit<8> remaining_hop_cnt;
    bit<4> instruction_mask_0003;
    bit<4> instruction_mask_0407;
    bit<4> instruction_mask_0811;
    bit<4> instruction_mask_1215;
    bit<16> rsvd3;
}

header switch_id_t {
	bit<32> sw_id;
}

header level1_port_id_t {
	bit<16> ingress_port_id;
	bit<16> egress_port_id;
}

header level2_port_id_t {
	bit<16> ingress_port_id;
	bit<16> egress_port_id;
}

header ingress_timestamp {
	bit<32> in_timestamp;
}

header egress_timestamp {
	bit<32> eg_timestamp;
}

header queue_info {
	bit<8>  id;
	bit<24> q_length;    
}

header hop_delay_t {
	bit<32> hop_delay;
}

//TX utilization of egress port
header egress_port_tx_util_t {
	bit<32> egress_port_tx_util;
}

struct headers {
    ethernet_t          	ethernet;
    ipv4_t              	ipv4;
    tcp_hdr             	tcp;
    shim_t              	shim;
    int_header_t        	int_header;
    switch_id_t         	switch_id;
	level1_port_id_t		level1_port_id;
	level2_port_id_t		level2_port_id;
    hop_delay_t         	hop_delay;
    queue_info          	queue;
    ingress_timestamp   	in_timestamp;
    egress_timestamp    	eg_timestamp;
	egress_port_tx_util_t   egress_port_tx_util;
}

//Both types are defined in P4 PSA 
struct ingress_input_metadata_t {
	PortId_t 	ingress_port;
	Timestamp_t ingress_timestamp;
}

//Switch internal variables
struct int_metadata_t {
    bit<16> insert_pos;
    bit<8>  int_hdr_word_len;
    bit<32> switch_id;
}

struct fwd_metadata_t {
    bit<16> 13_mtu;
    bit<16> checksum_state;
}

struct metadata {
	ingress_input_metadata_t	bridged_istd;
    int_metadata_t				int_metadata;
    fwd_metadata_t 				fwd_metadata;
}

error {
    BadIPv4HeaderChecksum
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in packet,
                	out headers hdr,
                	inout metadata meta,
                	in psa_ingress_parser_input_metadata_t istd) {
    
    InternetChecksum() ck;                

    state start {
        transition parse_ethernet;    
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4 : parse_ipv4;
            default accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        ck.clear();
        ck.add({
                hdr.ipv4.version,
                hdr.ipv4.ihl, 
                hdr.ipv4.dscp, 
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
        });

        verify(hdr.ipv4.hdrChecksum == ck.get(), error.BadIPv4HeaderChecksum);
        ck.clear();

        ck.subtract({
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.totalLen
        });

        transition select(hdr.ipv4.protocol) {
            6       : parse_tcp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        ck.subtract({
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seqNo,
            hdr.tcp.ackNo,
            hdr.tcp.dataOffset, hdr.tcp.res,
            hdr.tcp.flags,
            hdr.tcp.window,
            hdr.tcp.checksum,
            hdr.tcp.urgentPtr
        });
		meta.fwd_metadata.checksum_state = ck.get_state();
		transition accept;
    }
}

control IngressDeparser(packet_out packet,
						out metadata normal_meta,
						inout headers hdr, 
						in metadata meta,
						in psa_ingress_output_metadata_t istd) {
	apply{
		if(psa_normal(istd)){
			normal_meta = meta;
		}
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
	}						
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;

parser EgressParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    InternetChecksum() ck;                
    
    state start{
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6       : parse_tcp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
        DSCP_INT &&& DSCP_MASK: parse_shim;
        default: accept;
    }

    state parse_shim {
        packet.extract(hdr.shim);
        ck.subtract({
            hdr.shim.int_type,
            hdr.shim.rsvd1,
            hdr.shim.len,
            hdr.shim.dscp,
            hdr.shim.rsvd2
        });
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        ck.subtract({
            hdr.int_header.ver, 
            hdr.int_header.rep,
            hdr.int_header.c, 
            hdr.int_header.e,
            hdr.int_header.m, 
            hdr.int_header.rsvd1,
            hdr.int_header.rsvd2, 
            hdr.int_header.hop_metadata_len,
            hdr.int_header.remaining_hop_cnt,
            hdr.int_header.instruction_mask_0003,
            hdr.int_header.instruction_mask_0407,
            hdr.int_header.instruction_mask_0811,
            hdr.int_header.instruction_mask_1215,
            hdr.int_header.rsvd3
        });
        meta.fwd_metadata.checksum_state = ck.get_state();
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control EgressDeparser(packet_out packet,
                       inout headers hdr,
                       in metadata meta,
					   in psa_egress_output metadata_t istd,
					   in psa_egress_deparser_input_metadata_t edstd) {
    InternetChecksum() ck;
    
    apply {
        if (hdr.ipv4.isValid()) {
            ck.clear();
            ck.add({
                hdr.ipv4.version, 
                hdr.ipv4.ihl, 
                hdr.ipv4.dscp, 
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
            hdr.ipv4.hdrChecksum = ck.get();
        }
    
        ck.set_state(meta.fwd_metadata.checksum_state);

        if (hdr.ipv4.isValid()) {
            ck.add({
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.totalLen
            });
        }

        if (hdr.shim.isValid()) {
            ck.add({
                hdr.shim.int_type,
                hdr.shim.rsvd1,
                hdr.shim.len,
                hdr.shim.dscp,
                hdr.shim.rsvd2
            });
        }

        if (hdr.int_header.isValid()) {
            ck.add({
                hdr.int_header.ver,
                hdr.int_header.rep,
                hdr.int_header.c, 
                hdr.int_header.e,
                hdr.int_header.m, 
                hdr.int_header.rsvd1,
                hdr.int_header.rsvd2, 
                hdr.int_header.hop_metadata_len,
                hdr.int_header.remaining_hop_cnt,
                hdr.int_header.instruction_mask_0003,
                hdr.int_header.instruction_mask_0407,
                hdr.int_header.instruction_mask_0811,
                hdr.int_header.instruction_mask_1215,
                hdr.int_header.rsvd3
            });
        }

        if (hdr.switch_id.isValid()) {
            ck.add({hdr.switch_id.sw_id});
        }

        if (hdr.hop_delay.isValid()) {
            ck.add({hdr.hop_delay.hop_delay});
        }

		if (hdr.queue.isValid()) {
			ck.add({
				hdr.queue.id,
				hdr.queue.q_length
			});
		}

		if (hdr.in_timestamp.isValid()) {
			ck.add({hdr.in_timestamp.in_timestamp});
		}

		if (hdr.eg_timestamp.isValid()) {
			ck.add({hdr.eg_timestamp.eg_timestamp});
		}

		if (hdr.tcp.isValid()) {
			ck.add({
				hdr.tcp.srcPort,
				hdr.tcp.dstPort,
				hdr.tcp.seqNo,
				hdr.tcp.ackNo,
				hdr.tcp.dataOffset, hdr.tcp.res,
				hdr.tcp.flags,
				hdr.tcp.window,
				hdr.tcp.urgentPtr
			});
			hdr.tcp.checksum = ck.get();
		}

		if (hdr.level1_port_id.isValid()) {	
			ck.add({
				hdr.level1_port_id.ingress_port_id,
				hdr.level1_port_id.egress_port_id
			});
		}

		if (hdr.int_level2_port_ids.isValid()) {
			ck.add({
				hdr.level2_port_id.ingress_port_id,
				hdr.level2_port_id.egress_port_id
			});
		}
		
		if (hdr.int_egress_port_tx_util.isValid()) {
			ck.add({ hdr.egress_port_tx_util.egress_port_tx_util});
		}

		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
		packet.emit(hdr.shim);
		packet.emit(hdr.int_header);
		packet.emit(hdr.switch_id);
		packet.emit(hdr.level1_port_id);
		packet.emit(hdr.hop_delay);
		packet.emit(hdr.queue);
		packet.emit(hdr.in_timestamp);
		packet.emit(hdr.eg_timestamp);
		packet.emit(hdr.level2_port_id);
		packet.emit(hdr.egress_port_tx_util);
	}
	
}

//Bitmask used is 1111110000000000
control insert_int(inout headers hdr,
					in int_metadata_t int_metadata,
					in ingress_input_metadata_t bridged_istd,
					in psa_egress_input_metadata_t istd){
	
	//Set switch id on instruction 0
	action set_header_0 {
		hdr.switch_id.setValid();
		hdr.switch_id.sw_id = int_metadata.switch_id;
	}

	//Set level 1 ports on instruction 1
	action set_header_1{
		hdr.level1_port_id.setValid();
		hdr.level1_port_id.ingress_port_id = (bit<16>) bridged_istd.ingress_port;
		hdr.level1_port_id.egress_port_id = (bit<16>) bridged_istd.egress_port;
	}

	//Set hop delay on instruction 2
	action set_header_2 {
		hdr.hop_delay.setValid();
		hdr.hop_delay.hop_delay = (bit<32>) (istd.egress_timestamp - bridged_istd.ingress_timestamp);
	}

	//Set queue id and length on instruction 3
	action set_header_3 {
		hdr.queue.setValid();
		hdr.queue.id = 0xFF; //255
		hdr.queue.q_length = 0xFFFFFF;
	}

	//Set Ingress Timestamp on instruction 4
	action set_header_4 {
		hdr.in_timestamp.setValid();
		hdr.in_timestamp.in_timestamp = (bit<32>) bridged_istd.ingress_timestamp; 
	}

	//Set Egress Timestamp on instruction 5
	action set_header_5 {
		hdr.eg_timestamp.setValid();
		hdr.eg_timestamp.eg_timestamp = (bit<32>) istd.egress_timestamp; 
	}

	//Action functions below: lead flow according to the INT bitmask (MSB to LSB)
	//Represent each possible combination of bits in the 0-3 bits
	action set_bits_0003_i0{
		
	}

	action set_bits_0003_i1{
		set_header_3();
	}

	action set_bits_0003_i2{
		set_header_2();
	}

	action set_bits_0003_i3{
		set_header_3();
		set_header_2();
	}

	action set_bits_0003_i4() {
		set_header_1();
	}

	action set_bits_0003_i5() {
    	set_header_3();
    	set_header_1();
	}

	action set_bits_0003_i6() {
		set_header_2();
		set_header_1();
	}

    action set_bits_0003_i7() {
		set_header_3();
		set_header_2();
		set_header_1();
	}
	
	action set_bits_0003_i8() {
		set_header_0();	
	}

	action set_bits_0003_i9() {
		set_header_3();
		set_header_0();
	}

	action set_bits_0003_i10() {
		set_header_2();
		set_header_0();
	}

	action set_bits_0003_i11() {
		set_header_3();
		set_header_2();
		set_header_0();
	}

	action set_bits_0003_i12() {
		set_header_1();
		set_header_0();
	}	

	action set_bits_0003_i13() {
		set_header_3();
		set_header_1();
		set_header_0();
	}

	action set_bits_0003_i14() {
		set_header_2();
		set_header_1();
		set_header_0();
	}

	action set_bits_0003_i15() {
		set_header_3();
		set_header_2();
		set_header_1();
		set_header_0();
	}


	//Instructions from bit 7 to 4
	action set_bits_0407_i0 {} 
	action set_bits_0407_i1 {}
	action set_bits_0407_i2 {}
	action set_bits_0407_i3 {}

	action set_bits_0407_i4() {
		set_header_5();
	}

	action set_bits_0407_i5() {
    	set_header_5();
	}

	action set_bits_0407_i6() {
		set_header_5();
	}

    action set_bits_0407_i7() {
		set_header_5();
	}
	
	action set_bits_0407_i8() {
		set_header_4();	
	}

	action set_bits_0407_i9() {
		set_header_4();
	}

	action set_bits_0407_i10() {
		set_header_4();
	}

	action set_bits_0407_i11() {
		set_header_4();
	}

	action set_bits_0407_i12() {
		set_header_5();
		set_header_4();
	}	

	action set_bits_0407_i13() {
		set_header_5();
		set_header_4();
	}

	action set_bits_0407_i14() {
		set_header_5();
		set_header_4();
	}

	action set_bits_0407_i15() {
		set_header_5();
		set_header_4();
	}


	table int_bits_0003 {
		key = {
			hdr.int_header.instruction_mask_0407 : exact;
		}
		actions = {
			set_bits_0003_i0();
			set_bits_0003_i1();
			set_bits_0003_i2();
			set_bits_0003_i3();
			set_bits_0003_i4();
			set_bits_0003_i5();
			set_bits_0003_i6();
			set_bits_0003_i7();
			set_bits_0003_i8();
			set_bits_0003_i9();
			set_bits_0003_i10();
			set_bits_0003_i11();
			set_bits_0003_i12();
			set_bits_0003_i13();
			set_bits_0003_i14();
			set_bits_0003_i15();
		}
		default_action = set_bits_0003_i0();
		size = 16;
	}

	table int_bits_0407 {
		key = {
			hdr.int_header.instruction_mask_0407 : exact;
		}

		actions = {
			set_bits_0407_i0();
			set_bits_0407_i1();
			set_bits_0407_i2();
			set_bits_0407_i3();
			set_bits_0407_i4();
			set_bits_0407_i5();
			set_bits_0407_i6();
			set_bits_0407_i7();
			set_bits_0407_i8();
			set_bits_0407_i9();
			set_bits_0407_i10();
			set_bits_0407_i11();
			set_bits_0407_i12();
			set_bits_0407_i13();
			set_bits_0407_i14();
			set_bits_0407_i15();
		}

		default_action = set_bits_0407_i0();
		size = 16;
	}

	apply {
		int_bits_0003.apply();
		int_bits_0407.apply();	
	}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(), {
            hdr.ipv4.version,
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
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define H4_PORT 4
#define HDD_FILTER_ENTRIES 65535

const bit<16> TYPE_IPV4 = 0x0800;
typedef bit<48>  macAddr_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
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

struct metadata {
    bit<32> hhd_threshold;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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
    register<bit<32>>(HDD_FILTER_ENTRIES) hhd_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_hhd_threshold(bit<32> threshold) {
        meta.hhd_threshold = threshold;
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table hhd_threshold {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            drop;
            set_hhd_threshold;
        }
        default_action = drop();
    }    

    apply {  
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.ingress_port > 0 && standard_metadata.ingress_port < 4) {
                // We apply here the HHD algorithm
                if(hhd_threshold.apply().hit) {
                    bit<32> hhd_pkts;
                    bit<32> output_hash_ipSrc;

                    // Instead of calculating the hash, we could also emulate the modulo operation using the 
                    // following code:
                    // hash(output_hash_ipSrc, HashAlgorithm.identity, 0, {hdr.ipv4.srcAddr}, (bit<32>)HDD_FILTER_ENTRIES);
                    hash(output_hash_ipSrc, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr}, (bit<32>)HDD_FILTER_ENTRIES);

                    hhd_reg.read(hhd_pkts, output_hash_ipSrc);

                    if ((meta.hhd_threshold > 0) && (hhd_pkts >= meta.hhd_threshold)) {
                        drop();
                    } else {
                        forward(H4_PORT);
                        hhd_reg.write(output_hash_ipSrc, hhd_pkts + 1);
                    }
                }
            }
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
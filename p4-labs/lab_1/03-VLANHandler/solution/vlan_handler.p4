/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_VLAN = 0x8100;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header vlan_t {
    bit<3> pri;
    bit<1> dei;
    bit<12> vid; 
    bit<16> etherType;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    vlan_t vlan;
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
            TYPE_VLAN: parseVlan;
            default: accept;
        }
    }

    state parseVlan {
        packet.extract(hdr.vlan);
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

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;

        //Remove VLAN header from packet
        hdr.ethernet.etherType = hdr.vlan.etherType;
        hdr.vlan.setInvalid();
    }

    action add_vlan_hdr(bit<12> vid) {
        // Add VLAN header to packet
        hdr.vlan.setValid();
        hdr.vlan.pri = 0;
        hdr.vlan.dei = 0;
        hdr.vlan.vid = vid;
        hdr.vlan.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_VLAN;
    }

    table vlan_table {
        key = {
            hdr.vlan.vid : exact;
        }
        actions = {
            NoAction;
            forward;
        }
        default_action = NoAction;
    }

    table port_to_vlan {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            drop;
            add_vlan_hdr;
        }
        default_action = drop();
    }
    
    apply { 
        if (hdr.vlan.isValid()) {
            if (standard_metadata.ingress_port == 1) {
                switch (vlan_table.apply().action_run) {
                    NoAction: {
                        forward(2);
                    }
                }
            } else {
                drop();
            }
        } else {
            //VLAN header not present
            if (standard_metadata.ingress_port == 1) {
                drop();
            } else {
                port_to_vlan.apply();
                standard_metadata.egress_spec = 1;
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
        packet.emit(hdr.vlan);
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
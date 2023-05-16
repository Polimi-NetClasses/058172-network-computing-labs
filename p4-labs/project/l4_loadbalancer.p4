/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORT_WIDTH 9

#define CLIENT_PORT_IDX 1

#define BACKEND1_IDX 2
#define BACKEND2_IDX 3
#define BACKEND3_IDX 4
#define BACKEND4_IDX 5

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* TODO 1: Define ethernet header */

/* TODO 2: Define IPv4 header */

/* TODO 3: Define TCP header */

/* Metadata structure is used to pass information
 * across the actions, or the control block.
 * It is also used to pass information from the 
 * parser to the control blocks.
 */
struct metadata {
    bit<16> l4_payload_length;
    /* Used to understand if the packet belongs to a configured VIP */
    bit<1> pkt_is_virtual_ip;
    /* Used to keep track of the current backend assigned to a connection */
    bit<9> assigned_backend;
    /* TODO: Add here other metadata */
}

struct headers {
    /* TODO 4: Define here the headers structure */
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
        /* TODO 5: Parse Ethernet Header */
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        /* This information is used to recalculate the checksum 
         * in the MyComputeChecksum control block.
         * Since we modify the TCP header, we need to recompute the checksum.
         * We do it for you, so don't worry about it.
         */
        meta.l4_payload_length = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2);

        /* TODO 6: Define here the transition to the parse_tcp state */
    }

    state parse_tcp {
        /* TODO 7: Parse TCP header */
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
    /* TODO 11: Define here the register where you keep information about
     * the backend assigned to a connection.
     */

    /* TODO 13: Define here the register where you keep information about
     * the number of connections assigned to a backend
     */

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
        return;
    }

    /* Forward action */
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* This action is executed after a lookup on the vip_to_backend table */
    action update_backend_info(bit<32> ip, bit<16> port, bit<48> dstMac) {
        /* TODO 16: Update the packet fields before redirecting the 
         * packet to the backend.
         */
    }

    /* Define here all the other actions that you might need */

    /* This action is executed to check if the current packet is 
     * destined to a virtual IP configured on the load balancer.
     * This action is complete, you don't need to change it.
     */
    action is_virtual_ip(bit<1> val) {
        meta.pkt_is_virtual_ip = val;
    }

    /* This action is executed for packets coming from the backend servers.
     * You need to update the packet fields before redirecting the packet
     * to the client.
     * This action is executed after a lookup on the backend_to_vip table.
     */
    action backend_to_vip_conversion(bit<32> srcIP, bit<16> port, bit<48> srcMac) {
        /* TODO 18: Update the packet fields before redirecting the 
         * packet to the client.
         */
    }

    /* Table used map a backend index with its information */
    table vip_to_backend {
        key = {
            meta.assigned_backend : exact;
        }
        actions = {
            update_backend_info;
            drop;
        }
        default_action = drop();
    }

    /* Table used to understand if the current packet is destined 
     * to a configured virtual IP 
     */
    table virtual_ip {
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            is_virtual_ip;
            drop;
        }
        default_action = drop();
    }

    /* Table used to map a backend with the information about the VIP */
    table backend_to_vip {
        key = {
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            backend_to_vip_conversion;
            drop;
        }
        default_action = drop();
    }

    apply {  
        /* TODO 8: Check if the ingress port is the one connected to the client. */

        /* TODO 9: Verify whether the packet is destined for the Virtual IP 
         * If not, drop the packet.
         * If yes, continue with the ingress logic
         */

        /* TODO 10: Check if the current connection is already assigned to a specific 
         * backend server. 
         * If yes, forward the packet to the assigned backend (but first check the FIN or RST flag).
         * If not, assign a new backend to the connection (only is the packet has the SYN flag set)
         * otherwise, drop the packet.
         */

        /* TODO 12: Define the logic to assign a new backend to the connection.
         * You should assign the backend with the minimum number of connections.
         * If there are multiple backends with the same number of connections,
         * you should assign the backend with the lowest index.
         */

        /* TODO 14: If the packet is already assigned, and if the FIN or RST flags are enabled 
         * you should remove the assignment and decrement the number of connections
         * for the backend. Finally, forward the packet to the backend.
        */

        /* TODO 15: Before redirecting the packet from CLIENT to BACKEND, make sure
         * to update the packet fields (IP, MAC, etc.).
         */

        /* TODO 17: If the packet is coming from the other direction, make sure
         * to update the packet fields (IP, MAC, etc.) before redirecting it
         * to the client. The backend_to_vip table is used to get the information
         * about the VIP.
         */
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
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
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
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        // Note: the following does not support TCP options.
        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4_payload_length,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.cwr,
                hdr.tcp.ece,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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
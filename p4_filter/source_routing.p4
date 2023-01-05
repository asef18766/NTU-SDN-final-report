/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 0x6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cert2_t{
    bit<8> cert2_may_be_danger ;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    cert2_t[1000]           cert2;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

error { detect_malicious_code };

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
            TYPE_IPV4: check_ipv4_protocal;
            default: accept;
        }
    } 

    // check ipv4 protocal is tcp or not
    state check_ipv4_protocal{
        transition select(packet.lookahead<ipv4_t>().protocol){
            TYPE_TCP : parse_ipv4_tcp;
            default : parse_ipv4_other_protocol;
        }
    }

    state parse_ipv4_other_protocol{
        packet.extract(hdr.ipv4);
        transition accept;
    }

    // if its tls certificate packet, the length will longer than nomal packet
    state parse_ipv4_tcp {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.totalLen){
            2000 : parse_tcp_other_data;
            default: parse_tcp;
        }
    }

    // no other payload 
    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }

    // contain other payload 
    state parse_tcp_other_data{
        packet.extract(hdr.tcp);
        transition parse_cert_payload1;
    }

    state parse_cert_payload1{
        packet.extract(hdr.cert2.next);
        transition select(hdr.cert2.last.cert2_may_be_danger){
            0x78 : parse_cert_payload2 ;
            0x30 : accept ;
            default : parse_cert_payload1 ;
        }

    }

    state parse_cert_payload2{
        packet.extract(hdr.cert2.next);
        transition select(hdr.cert2.last.cert2_may_be_danger){
            0x6e : parse_cert_payload3;
            0x30 : accept ;
            default : parse_cert_payload1 ;
        }

    }

    state parse_cert_payload3{
        packet.extract(hdr.cert2.next);
        transition select(hdr.cert2.last.cert2_may_be_danger){
            0x2d : parse_cert_payload4;
            0x30 : accept ;
            default : parse_cert_payload1 ; 
        }
    }

    state parse_cert_payload4{
        packet.extract(hdr.cert2.next);
        transition select(hdr.cert2.last.cert2_may_be_danger){
            0x2d : malicious_detected;
            0x30 : accept ;
            default : parse_cert_payload1 ; 
        }
    }

    state malicious_detected{
        verify(false, error.detect_malicious_code);
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
    
    action accept_packet(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    
    table t {
        key = {
            hdr.ipv4.dstAddr: lpm;  // match label value
        }

        actions = {
            accept_packet;
            drop;
        }
        size = 1024;
	 default_action = drop();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError){
            mark_to_drop(standard_metadata);
            exit;
        }
        else {
            t.apply();
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.cert2);
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

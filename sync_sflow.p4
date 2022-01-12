/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>


/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<32> NOTSAMPLED = 0x00000000;
const bit<32> SAMPLED = 0x00000001;
const bit<3> SSFLOW_RESUBMIT = 0;
const bit<3> SSFLOW_MIRROR = 1;
const bit<4> SSFLOW_IG_MIRROR_INFO = 1;
const bit<4> SSFLOW_EG_MIRROR_INFO = 2;

/******** Internal Headers **********/

typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

const header_type_t HEADER_TYPE_BRIDGE = 0xB;
const header_type_t HEADER_TYPE_MIRROR_SSFLOW_IG = 0xC;
const header_type_t HEADER_TYPE_MIRROR_SSFLOW_EG = 0xD;

/* Table Sizes */
#ifndef IPV4_HOST_SIZE
  #define IPV4_HOST_SIZE 65536
#endif

#ifndef IPV4_LPM_SIZE 
  #define IPV4_LPM_SIZE 12288
#endif
#define INTERNAL_HEADER		   \
	header_type_t header_type; \
	header_info_t header_info

const int IPV4_HOST_TABLE_SIZE = IPV4_HOST_SIZE;
const int IPV4_LPM_TABLE_SIZE  = IPV4_LPM_SIZE;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */

enum bit<16> ether_type_t {
    TPID = 0x8100,
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    MPLS = 0x8847
}

enum bit<8> ip_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17
}

enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY = 2
}

enum bit<8> icmp_type_t {
    ECHO_REPLY = 0,
    ECHO_REQUEST = 8
}

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header option_h {
    bit<32> option;
}

header icmp_h {
    icmp_type_t msg_type;
    bit<8>      msg_code;
    bit<16>     checksum;
}

header arp_h {
    bit<16> 	 hw_type;
    ether_type_t proto_type;
    bit<8>	 hw_addr_len;
    bit<8> 	 proto_addr_len;
    arp_opcode_t opcode;
}

header arp_ipv4_h {
    mac_addr_t	 src_hw_addr;
    ipv4_addr_t  src_proto_addr;
    mac_addr_t	 dst_hw_addr;
    ipv4_addr_t	 dst_proto_addr;
}

header bridge_h {
    INTERNAL_HEADER;
}
header ssflow_ig_mirror_h {
    INTERNAL_HEADER;
    @flexible bit<16> original_len;
    @flexible MirrorId_t mirror_session;
    @flexible bit<48> ingress_mac_tstamp;
    @flexible bit<48> ingress_global_tstamp;
}
header inthdr_h {
    INTERNAL_HEADER;
}
typedef bit<16> index_t;
typedef bit<16> count_t;
typedef bit<32> data_t;


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    bridge_h	bridge;
    ethernet_h	ethernet;
    vlan_tag_h  vlan_tag;
    arp_h	arp;
    arp_ipv4_h	arp_ipv4;
    ipv4_h      ipv4;
    option_h	ipv4_options;
    icmp_h	icmp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    ipv4_addr_t		dst_ipv4;
    bool		ipv4_checksum_err;
    count_t		interval;
    index_t		index;
    index_t		mirror_index;
    header_type_t	mirror_header_type;
    header_info_t	mirror_header_info;
    MirrorId_t		mirror_session;
    bit<16>		original_len;
    bit<48>		ingress_mac_tstamp;
    bit<48>		ingress_global_tstamp;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
    (bool do_ipv4_checksum)
{
    Checksum() ipv4_checksum;
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
	transition initiate_meta;
    }

    state initiate_meta {
	meta.dst_ipv4 = 32w0;
	meta.ipv4_checksum_err = false;
	meta.interval = 16w0;
	meta.index = 16w0;
	meta.mirror_index = 16w0;
	meta.mirror_header_type = 4w0;
	meta.mirror_header_info = 4w0;
	meta.mirror_session = 10w0;
	meta.original_len = 16w0;
	meta.ingress_mac_tstamp = 48w0;
	meta.ingress_global_tstamp = 48w0;
	hdr.bridge.setValid();
	hdr.bridge.header_type = HEADER_TYPE_BRIDGE;
	hdr.bridge.header_info = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.TPID:  parse_vlan_tag;
            ether_type_t.IPV4:  parse_ipv4;
	    ether_type_t.ARP: 	parse_arp;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
	meta.dst_ipv4 = hdr.ipv4.dst_addr;
	if(do_ipv4_checksum) {
		ipv4_checksum.add(hdr.ipv4);
	}

	transition select(hdr.ipv4.ihl) {
		0x6: parse_ipv4_options;
        	default: parse_ipv4_no_options;
	}
    }
    
    state parse_ipv4_options {
	pkt.extract(hdr.ipv4_options);
	if(do_ipv4_checksum) {
		ipv4_checksum.add(hdr.ipv4_options);
	}
	transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
	if(do_ipv4_checksum) {
		meta.ipv4_checksum_err = ipv4_checksum.verify();
	}
	transition accept;
    }

    state parse_arp {
	pkt.extract(hdr.arp);
	transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
	    (0x0001, ether_type_t.IPV4) : parse_arp_ipv4;
	    default: accept;
	}
    }

    state parse_arp_ipv4 {
	pkt.extract(hdr.arp_ipv4);
	meta.dst_ipv4 = hdr.arp_ipv4.dst_proto_addr;
	transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    count_t c_now = 16w0;
    count_t mirror_point = 16w0;
    Register<count_t, index_t>(512)      sflow_counter;
    RegisterAction<count_t, index_t, count_t>(sflow_counter) mod_increase_counter =     {
        void apply(inout count_t reg_data, out count_t read_data) {
		if (reg_data + 1 == meta.interval) {
			reg_data = 0;
		}
		else {
			reg_data = reg_data + 1;
		}
                read_data = reg_data;
        }
    };
       RegisterAction<count_t, index_t, count_t>(sflow_counter) reset_counter = {
        void apply(inout count_t reg_data, out count_t read_data) {
		reg_data = 16w0;
                read_data = reg_data;
        }
    };


    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action send_rewrite(PortId_t port, bit<32> new_addr_da) {
	hdr.ipv4.dst_addr = new_addr_da;
	send(port);
    }
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action setmeta(count_t interval, index_t index, index_t mirror_index, MirrorId_t mirror_session){
        /* Counter */
	meta.interval = interval;
	meta.index = index;
        /* Mirror */
	meta.mirror_index = mirror_index;
	meta.mirror_header_type = HEADER_TYPE_MIRROR_SSFLOW_IG;
	meta.mirror_header_info = (header_info_t) SSFLOW_IG_MIRROR_INFO;
	meta.original_len = hdr.ipv4.total_len;
	meta.mirror_session = mirror_session;
	meta.ingress_mac_tstamp = ig_intr_md.ingress_mac_tstamp;
	meta.ingress_global_tstamp = ig_prsr_md.global_tstamp;
    }

    table ipv4_sampling {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            setmeta;
            @defaultonly NoAction;
        }        
        const default_action = NoAction();
        size = IPV4_HOST_TABLE_SIZE;
    }

    table ipv4_host {
        key = { meta.dst_ipv4 : exact; }
        actions = {
            send; send_rewrite; drop;
            @defaultonly NoAction;
        }        
        const default_action = NoAction();
        size = IPV4_HOST_TABLE_SIZE;
    }

    table ipv4_lpm {
        key     = { meta.dst_ipv4 : lpm; }
        actions = { send; drop; }
        
        default_action = send(64);
        size           = IPV4_LPM_TABLE_SIZE;
    }

    
    apply {
        if (hdr.ipv4.isValid()) {
	    if(ipv4_sampling.apply().hit) {
		if(hdr.ipv4_options.option == 32w1) {
			reset_counter.execute(meta.index);
		}
		else{
			c_now = mod_increase_counter.execute(meta.index);
			if(c_now == meta.mirror_index){
				ig_dprsr_md.mirror_type = SSFLOW_MIRROR;
				hdr.ipv4_options.setValid();
				hdr.ipv4_options.option = 32w1;
				hdr.ipv4.ihl = 0x6;
				hdr.ipv4.total_len = hdr.ipv4.total_len+4;
			}
		}
		
	    }
	    if (!meta.ipv4_checksum_err) {
                if (!ipv4_host.apply().hit) {
                    ipv4_lpm.apply();
                }
	    }
        } 
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Mirror() ssflow_mirror;
    apply {
	if(ig_dprsr_md.mirror_type == SSFLOW_MIRROR){
		ssflow_mirror.emit<ssflow_ig_mirror_h>(
		meta.mirror_session,
		{
			meta.mirror_header_type, meta.mirror_header_info,
			meta.original_len, meta.mirror_session,
			meta.ingress_mac_tstamp, meta.ingress_global_tstamp	
		}
		);
	}
	if(hdr.ipv4.isValid()) {
		hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.ipv4_options
            });
        }
	pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h	 monitor_ethernet;
    ipv4_h	 monitor_ipv4;
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    option_h	 ipv4_options;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bridge_h	bridge;
    ssflow_ig_mirror_h	ssflow_mirror;
    bit<4>	last_point;
    bool	ipv4_checksum_err;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
(bool do_ipv4_checksum)
{
    Checksum() ipv4_checksum;
    inthdr_h inthdr;
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
	inthdr = pkt.lookahead<inthdr_h>();
	meta.last_point = 0;
	meta.ipv4_checksum_err = false;
	transition select(inthdr.header_type,inthdr.header_info) {
		(HEADER_TYPE_BRIDGE, 0): parse_bridge;
		(HEADER_TYPE_MIRROR_SSFLOW_IG, 1): parse_ig_mirror_1;
    	}
    }
    state parse_bridge {
	pkt.extract(meta.bridge);
	transition parse_ethernet;
     }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.TPID:  parse_vlan_tag;
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
	if(do_ipv4_checksum) {
		ipv4_checksum.add(hdr.ipv4);
	}
	transition select(hdr.ipv4.ihl) {
		0x6: parse_ipv4_options;
        	default: parse_ipv4_no_options;
	}
    }
    
    state parse_ipv4_options {
	pkt.extract(hdr.ipv4_options);

	if(do_ipv4_checksum) {
		ipv4_checksum.add(hdr.ipv4_options);
	}
	transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
	if(do_ipv4_checksum) {
		meta.ipv4_checksum_err = ipv4_checksum.verify();
	}
	transition accept;
    }

    state parse_ig_mirror_1 {
	pkt.extract(meta.ssflow_mirror);
	transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{ 
    action send(){}
    action send_to_monitor(bit<48>src_mac, bit<32> src_ipv4, bit<48> dst_mac, bit<32> dst_ipv4, bit<8> sample_protocol) {
	hdr.monitor_ethernet.setValid();
	hdr.monitor_ethernet.dst_addr = dst_mac;
	hdr.monitor_ethernet.src_addr = src_mac;
	hdr.monitor_ethernet.ether_type = ether_type_t.IPV4;
	hdr.monitor_ipv4.setValid();
	hdr.monitor_ipv4.version = 0x4;
	hdr.monitor_ipv4.ihl = 0x5;
	hdr.monitor_ipv4.diffserv = 0x00;
	hdr.monitor_ipv4.total_len = meta.ssflow_mirror.original_len + 16w34;
	hdr.monitor_ipv4.identification = 0x0001;
	hdr.monitor_ipv4.ttl = 0x40;
	hdr.monitor_ipv4.protocol = sample_protocol;
	hdr.monitor_ipv4.hdr_checksum = 16w1;
	hdr.monitor_ipv4.src_addr = src_ipv4;
	hdr.monitor_ipv4.dst_addr = dst_ipv4;
	send();
    }
    action position_check(bit<4> last_point) {
	meta.last_point = last_point;
	send();
    }
    table ssflow_mirror {
	key = {meta.ssflow_mirror.mirror_session: exact; }
	actions = {send;send_to_monitor;}
	size = 1024;
    }
    table check_last {
	key = {hdr.ipv4.dst_addr: exact; }
	actions = {position_check;}
	size = 1024;
    }
    apply {
	if(!meta.ipv4_checksum_err){
		if(meta.ssflow_mirror.isValid()) {
			ssflow_mirror.apply();
		}
		else {
		    check_last.apply();
		    if(meta.last_point == 4w1 && hdr.ipv4_options.isValid()) {
			hdr.ipv4.ihl = 0x5;
			hdr.ipv4_options.setInvalid();
			hdr.ipv4.total_len = hdr.ipv4.total_len - 4;
	    	    }
		}
	}
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Checksum() egress_checksum;
    Checksum() Tomonitor_checksum;
    apply {
	if(hdr.ipv4.isValid()) {
		hdr.ipv4.hdr_checksum = egress_checksum.update({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.ipv4_options
            });
        }
	if(hdr.monitor_ipv4.isValid()){
		hdr.monitor_ipv4.hdr_checksum = Tomonitor_checksum.update({
                    hdr.monitor_ipv4.version,
                    hdr.monitor_ipv4.ihl,
                    hdr.monitor_ipv4.diffserv,
                    hdr.monitor_ipv4.total_len,
                    hdr.monitor_ipv4.identification,
                    hdr.monitor_ipv4.flags,
                    hdr.monitor_ipv4.frag_offset,
                    hdr.monitor_ipv4.ttl,
                    hdr.monitor_ipv4.protocol,
                    hdr.monitor_ipv4.src_addr,
                    hdr.monitor_ipv4.dst_addr
            });
	}

        pkt.emit(hdr);
    }

}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(do_ipv4_checksum=true),
    Ingress(),
    IngressDeparser(),
    EgressParser(do_ipv4_checksum=true),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

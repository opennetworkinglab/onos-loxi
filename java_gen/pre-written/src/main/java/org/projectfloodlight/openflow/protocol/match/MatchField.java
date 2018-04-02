package org.projectfloodlight.openflow.protocol.match;

import org.projectfloodlight.openflow.types.ArpOpcode;
import org.projectfloodlight.openflow.types.ClassId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.ICMPv4Code;
import org.projectfloodlight.openflow.types.ICMPv4Type;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IPv6FlowLabel;
import org.projectfloodlight.openflow.types.IpDscp;
import org.projectfloodlight.openflow.types.IpEcn;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.LagId;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBitMask128;
import org.projectfloodlight.openflow.types.OFBitMask512;
import org.projectfloodlight.openflow.types.OFBooleanValue;
import org.projectfloodlight.openflow.types.OFMetadata;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFValueType;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.PacketType;
import org.projectfloodlight.openflow.types.U16;
import org.projectfloodlight.openflow.types.U32;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.U8;
import org.projectfloodlight.openflow.types.UDF;
import org.projectfloodlight.openflow.types.VRF;
import org.projectfloodlight.openflow.types.VlanPcp;
import org.projectfloodlight.openflow.types.CircuitSignalID;
import org.projectfloodlight.openflow.types.OduSignalID;
import org.projectfloodlight.openflow.types.VxlanNI;
import org.projectfloodlight.openflow.types.VFI;

import java.util.Set;
import com.google.common.collect.ImmutableSet;

public class MatchField<F extends OFValueType<F>> {
    private final String name;
    public final MatchFields id;
    private final Set<Prerequisite<?>> prerequisites;

    private MatchField(final String name, final MatchFields id, Prerequisite<?>... prerequisites) {
        this.name = name;
        this.id = id;
        /* guaranteed non-null (private constructor); 'null' isn't passed as prerequisites */
        this.prerequisites = ImmutableSet.copyOf(prerequisites);
    }

    public final static MatchField<OFPort> IN_PORT =
            new MatchField<OFPort>("in_port", MatchFields.IN_PORT);

    public final static MatchField<OFPort> IN_PHY_PORT =
            new MatchField<OFPort>("in_phy_port", MatchFields.IN_PHY_PORT,
                    new Prerequisite<OFPort>(MatchField.IN_PORT));

    public final static MatchField<OFMetadata> METADATA =
            new MatchField<OFMetadata>("metadata", MatchFields.METADATA);

    public final static MatchField<MacAddress> ETH_DST =
            new MatchField<MacAddress>("eth_dst", MatchFields.ETH_DST);

    public final static MatchField<MacAddress> ETH_SRC =
            new MatchField<MacAddress>("eth_src", MatchFields.ETH_SRC);

    public final static MatchField<EthType> ETH_TYPE =
            new MatchField<EthType>("eth_type", MatchFields.ETH_TYPE);

    public final static MatchField<OFVlanVidMatch> VLAN_VID =
            new MatchField<OFVlanVidMatch>("vlan_vid", MatchFields.VLAN_VID);

    public final static MatchField<VlanPcp> VLAN_PCP =
            new MatchField<VlanPcp>("vlan_pcp", MatchFields.VLAN_PCP,
                    new Prerequisite<OFVlanVidMatch>(MatchField.VLAN_VID));

    public final static MatchField<IpDscp> IP_DSCP =
            new MatchField<IpDscp>("ip_dscp", MatchFields.IP_DSCP,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4, EthType.IPv6));

    public final static MatchField<IpEcn> IP_ECN =
            new MatchField<IpEcn>("ip_ecn", MatchFields.IP_ECN,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4, EthType.IPv6));

    public final static MatchField<IpProtocol> IP_PROTO =
            new MatchField<IpProtocol>("ip_proto", MatchFields.IP_PROTO,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4, EthType.IPv6));

    public final static MatchField<IPv4Address> IPV4_SRC =
            new MatchField<IPv4Address>("ipv4_src", MatchFields.IPV4_SRC,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4));

    public final static MatchField<IPv4Address> IPV4_DST =
            new MatchField<IPv4Address>("ipv4_dst", MatchFields.IPV4_DST,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4));
    
    public final static MatchField<U32> CONNTRACK_STATE =
            new MatchField<U32>("ct_state", MatchFields.CONNTRACK_STATE);

    public final static MatchField<U16> CONNTRACK_ZONE =
            new MatchField<U16>("ct_zone", MatchFields.CONNTRACK_ZONE);
    
    public final static MatchField<U32> CONNTRACK_MARK =
            new MatchField<U32>("ct_mark", MatchFields.CONNTRACK_MARK);
    
    public final static MatchField<TransportPort> TCP_SRC = new MatchField<TransportPort>(
            "tcp_src", MatchFields.TCP_SRC,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.TCP));

    public final static MatchField<TransportPort> TCP_DST = new MatchField<TransportPort>(
            "tcp_dst", MatchFields.TCP_DST,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.TCP));

    public final static MatchField<TransportPort> UDP_SRC = new MatchField<TransportPort>(
            "udp_src", MatchFields.UDP_SRC,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.UDP));

    public final static MatchField<TransportPort> UDP_DST = new MatchField<TransportPort>(
            "udp_dst", MatchFields.UDP_DST,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.UDP));

    public final static MatchField<TransportPort> SCTP_SRC = new MatchField<TransportPort>(
            "sctp_src", MatchFields.SCTP_SRC,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.SCTP));

    public final static MatchField<TransportPort> SCTP_DST = new MatchField<TransportPort>(
            "sctp_dst", MatchFields.SCTP_DST,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.SCTP));

    public final static MatchField<ICMPv4Type> ICMPV4_TYPE = new MatchField<ICMPv4Type>(
            "icmpv4_type", MatchFields.ICMPV4_TYPE,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.ICMP));

    public final static MatchField<ICMPv4Code> ICMPV4_CODE = new MatchField<ICMPv4Code>(
            "icmpv4_code", MatchFields.ICMPV4_CODE,
            new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.ICMP));

    public final static MatchField<ArpOpcode> ARP_OP = new MatchField<ArpOpcode>(
            "arp_op", MatchFields.ARP_OP,
            new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.ARP));

    public final static MatchField<IPv4Address> ARP_SPA =
            new MatchField<IPv4Address>("arp_spa", MatchFields.ARP_SPA,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.ARP));

    public final static MatchField<IPv4Address> ARP_TPA =
            new MatchField<IPv4Address>("arp_tpa", MatchFields.ARP_TPA,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.ARP));

    public final static MatchField<MacAddress> ARP_SHA =
            new MatchField<MacAddress>("arp_sha", MatchFields.ARP_SHA,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.ARP));

    public final static MatchField<MacAddress> ARP_THA =
            new MatchField<MacAddress>("arp_tha", MatchFields.ARP_THA,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.ARP));

    public final static MatchField<IPv6Address> IPV6_SRC =
            new MatchField<IPv6Address>("ipv6_src", MatchFields.IPV6_SRC,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<IPv6Address> IPV6_DST =
            new MatchField<IPv6Address>("ipv6_dst", MatchFields.IPV6_DST,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<IPv6FlowLabel> IPV6_FLABEL =
            new MatchField<IPv6FlowLabel>("ipv6_flabel", MatchFields.IPV6_FLABEL,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<U8> ICMPV6_TYPE =
            new MatchField<U8>("icmpv6_type", MatchFields.ICMPV6_TYPE,
                    new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.IPv6_ICMP));

    public final static MatchField<U8> ICMPV6_CODE =
            new MatchField<U8>("icmpv6_code", MatchFields.ICMPV6_CODE,
                    new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.IPv6_ICMP));

    public final static MatchField<IPv6Address> IPV6_ND_TARGET =
            new MatchField<IPv6Address>("ipv6_nd_target", MatchFields.IPV6_ND_TARGET,
                    new Prerequisite<U8>(MatchField.ICMPV6_TYPE, U8.of((short)135), U8.of((short)136)));

    public final static MatchField<MacAddress> IPV6_ND_SLL =
            new MatchField<MacAddress>("ipv6_nd_sll", MatchFields.IPV6_ND_SLL,
                    new Prerequisite<U8>(MatchField.ICMPV6_TYPE, U8.of((short)135)));

    public final static MatchField<MacAddress> IPV6_ND_TLL =
            new MatchField<MacAddress>("ipv6_nd_tll", MatchFields.IPV6_ND_TLL,
                    new Prerequisite<U8>(MatchField.ICMPV6_TYPE, U8.of((short)136)));

    public final static MatchField<U32> MPLS_LABEL =
            new MatchField<U32>("mpls_label", MatchFields.MPLS_LABEL,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.MPLS_UNICAST, EthType.MPLS_MULTICAST));

    public final static MatchField<U8> MPLS_TC =
            new MatchField<U8>("mpls_tc", MatchFields.MPLS_TC,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.MPLS_UNICAST, EthType.MPLS_MULTICAST));

    public final static MatchField<OFBooleanValue> MPLS_BOS =
            new MatchField<OFBooleanValue>("mpls_bos", MatchFields.MPLS_BOS,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.MPLS_UNICAST, EthType.MPLS_MULTICAST));

    public final static MatchField<U64> TUNNEL_ID =
            new MatchField<U64>("tunnel_id", MatchFields.TUNNEL_ID);

    public final static MatchField<U16> IPV6_EXTHDR =
            new MatchField<U16>("ipv6_exthdr", MatchFields.IPV6_EXTHDR,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<OFBooleanValue> PBB_UCA =
            new MatchField<OFBooleanValue>("pbb_uca", MatchFields.PBB_UCA,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.PBB));

    public final static MatchField<U16> TCP_FLAGS =
            new MatchField<U16>("tcp_flags", MatchFields.TCP_FLAGS,
                    new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.TCP));

    public final static MatchField<U16> OVS_TCP_FLAGS =
            new MatchField<U16>("ovs_tcp_flags", MatchFields.OVS_TCP_FLAGS,
                    new Prerequisite<IpProtocol>(MatchField.IP_PROTO, IpProtocol.TCP));

    public final static MatchField<PacketType> PACKET_TYPE =
            new MatchField<PacketType>("packet_type", MatchFields.PACKET_TYPE);

    public final static MatchField<OFPort> ACTSET_OUTPUT =
            new MatchField<OFPort>("actset_output", MatchFields.ACTSET_OUTPUT);

    public final static MatchField<IPv4Address> TUNNEL_IPV4_SRC =
            new MatchField<IPv4Address>("tunnel_ipv4_src", MatchFields.TUNNEL_IPV4_SRC,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4));

    public final static MatchField<IPv4Address> TUNNEL_IPV4_DST =
            new MatchField<IPv4Address>("tunnel_ipv4_dst", MatchFields.TUNNEL_IPV4_DST,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4));

    public final static MatchField<IPv6Address> TUNNEL_IPV6_SRC =
            new MatchField<IPv6Address>("tunnel_ipv6_src", MatchFields.TUNNEL_IPV6_SRC,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<IPv6Address> TUNNEL_IPV6_DST =
            new MatchField<IPv6Address>("tunnel_ipv6_dst", MatchFields.TUNNEL_IPV6_DST,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv6));

    public final static MatchField<OFBitMask128> BSN_IN_PORTS_128 =
            new MatchField<OFBitMask128>("bsn_in_ports_128", MatchFields.BSN_IN_PORTS_128);

    public final static MatchField<OFBitMask512> BSN_IN_PORTS_512 =
            new MatchField<OFBitMask512>("bsn_in_ports_512", MatchFields.BSN_IN_PORTS_512);

    public final static MatchField<LagId> BSN_LAG_ID =
            new MatchField<LagId>("bsn_lag_id", MatchFields.BSN_LAG_ID);

    public final static MatchField<VRF> BSN_VRF =
            new MatchField<VRF>("bsn_vrf", MatchFields.BSN_VRF);

    public final static MatchField<OFBooleanValue> BSN_GLOBAL_VRF_ALLOWED =
            new MatchField<OFBooleanValue>("bsn_global_vrf_allowed", MatchFields.BSN_GLOBAL_VRF_ALLOWED);

    public final static MatchField<ClassId> BSN_L3_INTERFACE_CLASS_ID =
            new MatchField<ClassId>("bsn_l3_interface_class_id", MatchFields.BSN_L3_INTERFACE_CLASS_ID);

    public final static MatchField<ClassId> BSN_L3_SRC_CLASS_ID =
            new MatchField<ClassId>("bsn_l3_src_class_id", MatchFields.BSN_L3_SRC_CLASS_ID);

    public final static MatchField<ClassId> BSN_L3_DST_CLASS_ID =
            new MatchField<ClassId>("bsn_l3_dst_class_id", MatchFields.BSN_L3_DST_CLASS_ID);

    public final static MatchField<ClassId> BSN_EGR_PORT_GROUP_ID =
            new MatchField<ClassId>("bsn_egr_port_group_id", MatchFields.BSN_EGR_PORT_GROUP_ID);

    public final static MatchField<ClassId> BSN_INGRESS_PORT_GROUP_ID =
            new MatchField<ClassId>("bsn_ingress_port_group_id", MatchFields.BSN_INGRESS_PORT_GROUP_ID);

    public final static MatchField<UDF> BSN_UDF0 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF0);

    public final static MatchField<UDF> BSN_UDF1 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF1);

    public final static MatchField<UDF> BSN_UDF2 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF2);

    public final static MatchField<UDF> BSN_UDF3 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF3);

    public final static MatchField<UDF> BSN_UDF4 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF4);

    public final static MatchField<UDF> BSN_UDF5 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF5);

    public final static MatchField<UDF> BSN_UDF6 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF6);

    public final static MatchField<UDF> BSN_UDF7 =
            new MatchField<UDF>("bsn_udf", MatchFields.BSN_UDF7);

    public final static MatchField<U16> BSN_TCP_FLAGS =
            new MatchField<U16>("bsn_tcp_flags", MatchFields.BSN_TCP_FLAGS);

    public final static MatchField<ClassId> BSN_VLAN_XLATE_PORT_GROUP_ID =
            new MatchField<ClassId>("bsn_vlan_xlate_port_group_id", MatchFields.BSN_VLAN_XLATE_PORT_GROUP_ID);

    public final static MatchField<U8> OCH_SIGTYPE =
            new MatchField<U8>("och_sigtype",
                                    MatchFields.OCH_SIGTYPE);

    public final static MatchField<U8> OCH_SIGTYPE_BASIC =
            new MatchField<U8>("och_sigtype_basic",
                                    MatchFields.OCH_SIGTYPE_BASIC);

    public final static MatchField<CircuitSignalID> OCH_SIGID =
            new MatchField<CircuitSignalID>("och_sigid",
                                    MatchFields.OCH_SIGID);

    public final static MatchField<CircuitSignalID> OCH_SIGID_BASIC =
            new MatchField<CircuitSignalID>("och_sigid_basic",
                                    MatchFields.OCH_SIGID);

    public final static MatchField<U32> OCH_SIGATT =
            new MatchField<U32>("och_sigatt",
                                    MatchFields.OCH_SIGATT);

    public final static MatchField<U32> OCH_SIGATT_BASIC =
            new MatchField<U32>("och_sigatt_basic",
                                    MatchFields.OCH_SIGATT_BASIC);

    public final static MatchField<OFBooleanValue> BSN_L2_CACHE_HIT =
            new MatchField<OFBooleanValue>("bsn_l2_cache_hit", MatchFields.BSN_L2_CACHE_HIT);

    public final static MatchField<VxlanNI> BSN_VXLAN_NETWORK_ID =
            new MatchField<VxlanNI>("bsn_vxlan_network_id", MatchFields.BSN_VXLAN_NETWORK_ID);

    public final static MatchField<MacAddress> BSN_INNER_ETH_DST =
            new MatchField<MacAddress>("bsn_inner_eth_dst", MatchFields.BSN_INNER_ETH_DST);

    public final static MatchField<MacAddress> BSN_INNER_ETH_SRC =
            new MatchField<MacAddress>("bsn_inner_eth_src", MatchFields.BSN_INNER_ETH_SRC);

    public final static MatchField<OFVlanVidMatch> BSN_INNER_VLAN_VID =
            new MatchField<OFVlanVidMatch>("bsn_inner_vlan_vid", MatchFields.BSN_INNER_VLAN_VID);

    public final static MatchField<OduSignalID> EXP_ODU_SIG_ID =
            new MatchField<OduSignalID>("exp_odu_sig_id", MatchFields.EXP_ODU_SIG_ID);

    public final static MatchField<U8> EXP_ODU_SIGTYPE =
            new MatchField<U8>("exp_odu_sigtype", MatchFields.EXP_ODU_SIGTYPE);

    public final static MatchField<CircuitSignalID> EXP_OCH_SIG_ID =
            new MatchField<CircuitSignalID>("exp_och_sig_id", MatchFields.EXP_OCH_SIG_ID);

    public final static MatchField<U8> EXP_OCH_SIGTYPE =
            new MatchField<U8>("exp_och_sigtype", MatchFields.EXP_OCH_SIGTYPE);

    public final static MatchField<U32> REG0 =
            new MatchField<U32>("reg0", MatchFields.REG0);

    public final static MatchField<U32> REG1 =
            new MatchField<U32>("reg1", MatchFields.REG1);

    public final static MatchField<U32> REG2 =
            new MatchField<U32>("reg2", MatchFields.REG2);

    public final static MatchField<U32> REG3 =
            new MatchField<U32>("reg3", MatchFields.REG3);

    public final static MatchField<U32> REG4 =
            new MatchField<U32>("reg4", MatchFields.REG4);

    public final static MatchField<U32> REG5 =
            new MatchField<U32>("reg5", MatchFields.REG5);

    public final static MatchField<U32> REG6 =
            new MatchField<U32>("reg6", MatchFields.REG6);

    public final static MatchField<U32> REG7 =
            new MatchField<U32>("reg7", MatchFields.REG7);

    public final static MatchField<U32> NSP =
            new MatchField<U32>("nsp", MatchFields.NSP);

    public final static MatchField<U8> NSI =
            new MatchField<U8>("nsi", MatchFields.NSI);

    public final static MatchField<U32> NSH_C1 =
            new MatchField<U32>("nshc1", MatchFields.NSH_C1);

    public final static MatchField<U32> NSH_C2 =
            new MatchField<U32>("nshc2", MatchFields.NSH_C2);

    public final static MatchField<U32> NSH_C3 =
            new MatchField<U32>("nshc3", MatchFields.NSH_C3);

    public final static MatchField<U32> NSH_C4 =
            new MatchField<U32>("nshc4", MatchFields.NSH_C4);

    public final static MatchField<U8> NSH_MDTYPE =
            new MatchField<U8>("nsh_mdtype", MatchFields.NSH_MDTYPE);

    public final static MatchField<U8> NSH_NP =
            new MatchField<U8>("nsh_np", MatchFields.NSH_NP);

    public final static MatchField<MacAddress> ENCAP_ETH_SRC =
            new MatchField<MacAddress>("encap_eth_src", MatchFields.ENCAP_ETH_SRC);

    public final static MatchField<MacAddress> ENCAP_ETH_DST =
            new MatchField<MacAddress>("encap_eth_dst", MatchFields.ENCAP_ETH_DST);

    public final static MatchField<U16> ENCAP_ETH_TYPE =
            new MatchField<U16>("encap_eth_type", MatchFields.ENCAP_ETH_TYPE);

    public final static MatchField<U16> TUN_FLAGS =
            new MatchField<U16>("tun_flags", MatchFields.TUN_FLAGS);

    public final static MatchField<U16> TUN_GBP_ID =
            new MatchField<U16>("tun_gbp_id", MatchFields.TUN_GBP_ID);

    public final static MatchField<U8> TUN_GBP_FLAGS =
            new MatchField<U8>("tun_gbp_flags", MatchFields.TUN_GBP_FLAGS);

    public final static MatchField<U8> TUN_GPE_NP =
            new MatchField<U8>("tun_gpe_np", MatchFields.TUN_GPE_NP);

    public final static MatchField<U8> TUN_GPE_FLAGS =
            new MatchField<U8>("tun_gpe_flags", MatchFields.TUN_GPE_NP);

    public final static MatchField<U16> OFDPA_MPLS_TYPE =
            new MatchField<U16>("ofdpa_mpls_type", MatchFields.OFDPA_MPLS_TYPE);

    public final static MatchField<U8> OFDPA_QOS_INDEX =
            new MatchField<U8>("ofdpa_qos_index", MatchFields.OFDPA_QOS_INDEX);

    public final static MatchField<U32> OFDPA_MPLS_L2_PORT =
            new MatchField<U32>("ofdpa_mpls_l2_port", MatchFields.OFDPA_MPLS_L2_PORT);

    public final static MatchField<U16> OFDPA_OVID =
            new MatchField<U16>("ofdpa_ovid", MatchFields.OFDPA_OVID,
                new Prerequisite<OFVlanVidMatch>(MatchField.VLAN_VID));

    public final static MatchField<U32> OFDPA_ACTSET_OUTPUT =
            new MatchField<U32>("ofdpa_actset_output", MatchFields.OFDPA_ACTSET_OUTPUT);

    public final static MatchField<U8> OFDPA_ALLOW_VLAN_TRANSLATION =
            new MatchField<U8>("ofdpa_allow_vlan_translation", MatchFields.OFDPA_ALLOW_VLAN_TRANSLATION);

    public final static MatchField<VFI> BSN_VFI =
            new MatchField<VFI>("bsn_vfi", MatchFields.BSN_VFI);

    public final static MatchField<OFBooleanValue> BSN_IP_FRAGMENTATION =
            new MatchField<OFBooleanValue>("bsn_ip_fragmentation", MatchFields.BSN_IP_FRAGMENTATION,
                    new Prerequisite<EthType>(MatchField.ETH_TYPE, EthType.IPv4, EthType.IPv6));

    public String getName() {
        return name;
    }

    public boolean arePrerequisitesOK(Match match) {
        for (Prerequisite<?> p : this.prerequisites) {
            if (!p.isSatisfied(match)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Retrieve what also must be matched in order to
     * use this particular MatchField.
     *
     * @return unmodifiable view of the prerequisites
     */
    public Set<Prerequisite<?>> getPrerequisites() {
        /* assumes non-null; guaranteed by constructor */
        return this.prerequisites;
    }

}

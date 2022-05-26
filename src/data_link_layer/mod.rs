use nom::{bytes::complete::take, Err, IResult};
use nom::character::complete::u32;

use arp::*;
use switch::*;

use crate::config::*;
use crate::error::{Error, Result};
use crate::topograph::{
    graph::*,
    net_util::*,
};

pub mod arp;
pub mod switch;

pub trait ToBytes {
    fn to_bytes(self) -> Vec<u8>;
}

#[derive(Default, Debug)]
pub struct EthernetHeader {
    dst_mac: MAC,
    src_mac: MAC,
    eth_type: u16,
    payload: Vec<u8>,
    FCS: u32,
}

impl ToBytes for EthernetHeader {
    fn to_bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.dst_mac.0);
        bytes.extend_from_slice(&self.src_mac.0);
        bytes.extend_from_slice(&self.eth_type.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.FCS.to_be_bytes());

        bytes
    }
}

fn take6(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(6u8)(input)
}

fn take4(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(4u8)(input)
}

fn take2(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(2u8)(input)
}

fn take1(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(1u8)(input)
}

fn take_payload(len: usize, input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(len)(input)
}


impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let len = bytes.len();
        let (bytes, dst_mac) = take6(bytes).unwrap();
        let (bytes, src_mac) = take6(bytes).unwrap();
        let (bytes, eth_type) = take2(bytes).unwrap();
        let (bytes, payload) = take_payload(len - 18, bytes).unwrap();
        let (bytes, FCS) = take4(bytes).unwrap();
        let hdr = EthernetHeader {
            dst_mac: MAC(dst_mac.try_into().unwrap()),
            src_mac: MAC(src_mac.try_into().unwrap()),
            eth_type: u16::from_be_bytes(eth_type.try_into().unwrap()),
            payload: payload.to_vec(),
            FCS: u32::from_be_bytes(FCS.try_into().unwrap()),
        };
        Ok(hdr)
    }
    #[inline]
    pub fn set_des_mac(&mut self, mac: MAC) {
        self.dst_mac = mac;
    }

    #[inline]
    pub fn set_src_mac(&mut self, mac: MAC) {
        self.src_mac = mac;
    }

    #[inline]
    pub fn set_type(&mut self, eth_type: u16) {
        self.eth_type = eth_type;
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    #[inline]
    pub fn is_broadcast_mac(&self) -> bool {
        self.dst_mac.eq(&MAC([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))
    }
}


pub fn layer2_frame_recv(node: &mut Node, interface: &Interface, pkt: &[u8]) -> Result<()> {
    let ethernet_hdr = EthernetHeader::from_bytes(pkt)?;
    match l2_frame_recv_qualify_on_interface(interface, &ethernet_hdr) {
        true => {
            println!("L2 Frame Accepted.");
            if interface.is_l3_mode() {
                match ethernet_hdr.eth_type {
                    ARP_MSG => {
                        let arp_hdr = ARPHeader::from_bytes(&ethernet_hdr.payload)?;
                        match arp_hdr.op_code() {
                            ARP_BROAD_REQ => {
                                process_arp_broadcast_request(node,
                                                              interface,
                                                              &ethernet_hdr,
                                                              &arp_hdr)?;
                            }
                            ARP_REPLY => {
                                process_arp_reply_msg(node,
                                                      interface,
                                                      &ethernet_hdr,
                                                      &arp_hdr)?;
                            }
                            _ => unreachable!()
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                match interface.l2_mode() {
                    &InterfaceMode::ACCESS | &InterfaceMode::TRUNK => { switch_recv_frame(interface, pkt)?; }
                    _ => {}
                }
            }
        }
        false => {
            println!("L2 Frame rejected.");
        }
    }
    Ok(())
}

pub fn l2_frame_recv_qualify_on_interface(interface: &Interface, ethernet_hdt: &EthernetHeader) -> bool {
    if !interface.is_l3_mode() &&
        *interface.l2_mode() == InterfaceMode::UNKNOWN {
        return false;
    }
    if !interface.is_l3_mode() &&
        (*interface.l2_mode() == InterfaceMode::ACCESS ||
            *interface.l2_mode() == InterfaceMode::TRUNK) {
        return true;
    }
    if interface.is_l3_mode() &&
        interface.get_mac_address().eq(&ethernet_hdt.dst_mac) {
        return true;
    }
    if interface.is_l3_mode() && ethernet_hdt.is_broadcast_mac() {
        return true;
    }
    false
}


#[cfg(test)]
mod test {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_ethernet_hdr() -> Result<()> {
        let ethernet_hdr = EthernetHeader {
            dst_mac: MAC([1, 2, 3, 4, 5, 6]),
            src_mac: MAC([2, 3, 4, 5, 6, 7]),
            eth_type: 11,
            payload: vec![b'a', b'a', b'a', b'a', b'a', b'a'],
            FCS: 12,
        };
        let bytes = ethernet_hdr.to_bytes();
        println!("{:?}", bytes);
        let hdr = EthernetHeader::from_bytes(&bytes)?;
        println!("{:?}", hdr);
        Ok(())
    }

    #[test]
    fn test_arp() -> Result<()> {
        let topology_anme = b"   test_graph   ";
        let mut graph = Graph::new(topology_anme);
        let node1 = graph.add_node(b"   test_node1   ");
        let node2 = graph.add_node(b"   test_node2   ");
        let node3 = graph.add_node(b"   test_node3   ");

        graph.insert_link(node1, node2, b"      eth0/0    ", b"      eth0/1    ", 1);
        graph.insert_link(node2, node3, b"      eth0/2    ", b"      eth0/3    ", 1);
        graph.insert_link(node3, node1, b"      eth0/4    ", b"      eth0/5    ", 1);

        unsafe {
            (*node1).set_loopback_address(IP([127, 0, 0, 1]));
            (*node1).set_intf_ip_address(b"      eth0/5    ", IP([194, 168, 0, 15]), 24);
            (*node1).set_intf_ip_address(b"      eth0/0    ", IP([192, 168, 0, 10]), 24);

            (*node2).set_loopback_address(IP([127, 0, 0, 1]));
            (*node2).set_intf_ip_address(b"      eth0/1    ", IP([192, 168, 0, 11]), 24);
            (*node2).set_intf_ip_address(b"      eth0/2    ", IP([193, 168, 0, 12]), 24);

            (*node3).set_loopback_address(IP([127, 0, 0, 1]));
            (*node3).set_intf_ip_address(b"      eth0/3    ", IP([193, 168, 0, 13]), 24);
            (*node3).set_intf_ip_address(b"      eth0/4    ", IP([194, 168, 0, 14]), 24);

            (*node1).init_udp_sock(3456);
            (*node2).init_udp_sock(40014);
            (*node3).init_udp_sock(40013);

            //graph.dump_graph();

            graph.start_pkt_receiver_thread();
            send_arp_broadcast_request(&(*node1), IP([192, 168, 0, 11]))?;
            sleep(Duration::from_millis(3000));
            (*node1).get_arp_table().dump();
            send_arp_broadcast_request(&(*node1), IP([194, 168, 0, 14]))?;
            sleep(Duration::from_millis(3000));
            (*node1).get_arp_table().dump();
        }

        Ok(())
    }

    #[test]
    fn test_switch() -> Result<()>{
        let topology_anme = b"  switch_graph  ";
        let mut graph = Graph::new(topology_anme);

        let node1 = graph.add_node(b"   test_node1   ");
        let node2 = graph.add_node(b"   test_node2   ");
        let node3 = graph.add_node(b"   test_node3   ");
        let node4 = graph.add_node(b"   test_node4   ");
        let switch = graph.add_node(b"   test_switch  ");

        graph.insert_link(node1, switch, b"      eth0/1    ", b"      eth0/5    ", 1);
        graph.insert_link(node2, switch, b"      eth0/2    ", b"      eth0/6    ", 1);
        graph.insert_link(node3, switch, b"      eth0/3    ", b"      eth0/7    ", 1);
        graph.insert_link(node4, switch, b"      eth0/4    ", b"      eth0/8    ", 1);

        unsafe {
            (*node1).set_loopback_address(IP([127, 0, 0, 1]));
            (*node1).set_intf_ip_address(b"      eth0/1    ", IP([192, 168, 0, 11]), 24);
            let intf1 = (*node1).get_node_if_by_name(b"      eth0/1    ");

            (*node2).set_loopback_address(IP([127, 0, 0, 1]));
            (*node2).set_intf_ip_address(b"      eth0/2    ", IP([193, 168, 0, 12]), 24);
            let intf2 = (*node2).get_node_if_by_name(b"      eth0/2    ");

            (*node3).set_loopback_address(IP([127, 0, 0, 1]));
            (*node3).set_intf_ip_address(b"      eth0/3    ", IP([193, 168, 0, 13]), 24);
            let intf3 = (*node3).get_node_if_by_name(b"      eth0/3    ");

            (*node4).set_loopback_address(IP([127, 0, 0, 1]));
            (*node4).set_intf_ip_address(b"      eth0/4    ", IP([193, 168, 0, 14]), 24);
            let intf4 = (*node4).get_node_if_by_name(b"      eth0/4    ");

            (*switch).set_loopback_address(IP([127, 0, 0, 1]));
            (*switch).set_interfaces_mode(InterfaceMode::ACCESS);

            (*node1).init_udp_sock(40011);
            (*node2).init_udp_sock(40012);
            (*node3).init_udp_sock(40013);
            (*node4).init_udp_sock(40014);
            (*switch).init_udp_sock(3456);

            graph.start_pkt_receiver_thread();

            let mut eth1 = EthernetHeader::default();
            eth1.set_des_mac((*intf2).get_mac_address());
            eth1.set_src_mac((*intf1).get_mac_address());
            eth1.set_payload(vec![1,2,3]);


            let mut eth2 = EthernetHeader::default();
            eth2.set_des_mac((*intf4).get_mac_address());
            eth2.set_src_mac((*intf3).get_mac_address());
            eth2.set_payload(vec![1,2,3]);

            send_arp_broadcast_request(&(*node1), IP([192, 168, 0, 11]))?;

            (*node1).send_pkt_out(&(*intf1).get_if_name(), &eth1.to_bytes())?;
            (*node3).send_pkt_out(&(*intf3).get_if_name(), &eth2.to_bytes())?;
            sleep(Duration::from_millis(3000));
            (*switch).get_mac_lable().dump();

            Ok(())
        }



    }
}
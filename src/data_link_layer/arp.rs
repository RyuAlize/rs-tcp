use std::collections::LinkedList;
use std::fmt::{Display, Formatter};
use memoffset::offset_of;
use crate::error::{Result, Error};
use super::*;

const ARP_BROAD_REQ: u16 = 1;
const ARP_REPLY: u16 = 2;
const ARP_MSG: u16 = 809;

pub struct ARPHeader {
    hw_type: u16,        /*1 for ethernet cable*/
    proto_type: u16,     /*0x0800 for IPV4*/
    hw_addr_len: u8,     /*6 for MAC*/
    proto_addr_type:u8,  /*4 for IPV4*/
    op_code: u16,        /*req or reply*/
    src_mac: MAC,
    src_ip: IP,
    des_mac: MAC,
    des_ip: IP,
}

impl ToBytes for ARPHeader {
    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.hw_type.to_be_bytes());
        bytes.extend_from_slice(&self.proto_type.to_be_bytes());
        bytes.extend_from_slice(&self.hw_addr_len.to_be_bytes());
        bytes.extend_from_slice(&self.op_code.to_be_bytes());
        bytes.extend_from_slice(&self.src_mac.0);
        bytes.extend_from_slice(&self.src_ip.0);
        bytes.extend_from_slice(&self.des_mac.0);
        bytes.extend_from_slice(&self.des_ip.0);

        bytes
    }

}

impl ARPHeader{
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (bytes, hw_type) = take2(bytes).unwrap();
        let (bytes, proto_type) = take2(bytes).unwrap();
        let (bytes, hw_addr_len) = take1(bytes).unwrap();
        let (bytes, proto_addr_type) = take1(bytes).unwrap();
        let (bytes, op_code) = take2(bytes).unwrap();
        let (bytes, src_mac) = take6(bytes).unwrap();
        let (bytes, src_ip) = take4(bytes).unwrap();
        let (bytes, dst_mac) = take6(bytes).unwrap();
        let (bytes, dst_ip) = take4(bytes).unwrap();
        Ok(Self{
            hw_type: u16::from_be_bytes(hw_type.try_into().unwrap()),
            proto_type: u16::from_be_bytes(proto_type.try_into().unwrap()),
            hw_addr_len: u8::from_be_bytes(hw_addr_len.try_into().unwrap()),
            proto_addr_type: u8::from_be_bytes(proto_addr_type.try_into().unwrap()),
            op_code: u16::from_be_bytes(op_code.try_into().unwrap()),
            src_mac: MAC(src_mac.try_into().unwrap()),
            src_ip: IP(src_ip.try_into().unwrap()),
            des_mac: MAC(dst_mac.try_into().unwrap()),
            des_ip: IP(dst_ip.try_into().unwrap())
        })
    }
}

pub struct ARPPendingEntry {

    //arp_processing_fn:
}

pub struct ARPEntry {
    ip_addr: IP,
    mac_addr: MAC,
    oif_name: [u8; IF_NAME_SIZE],
    is_sane: bool,
    //arg_pending_list: LinkedList<ARPPendingEntry>,
}

impl PartialEq for ARPEntry {
    fn eq(&self, other: &Self) -> bool {
        self.ip_addr.eq(&other.ip_addr)
            && self.mac_addr.eq(&other.mac_addr)
            && self.oif_name.eq(&other.oif_name)
            && self.is_sane == other.is_sane
            && self.is_sane == false
    }
}

impl ARPEntry {
    pub fn delete(mut self) {
        self.delete_pending_entries();
    }

    pub fn delete_pending_entries(&mut self) {

    }

    pub fn add_pending_entry(&mut self, pkt: &[u8]) {

    }
}

pub struct ARPTable {
    arp_entries: LinkedList<ARPEntry>,
}

impl ARPTable {
    pub fn init() -> Self {
        Self{
            arp_entries: LinkedList::new(),
        }
    }

    pub fn lookup(&self, ip: IP) -> Option<&ARPEntry> {
        self.arp_entries.iter().find(|&entry| entry.ip_addr.eq(&ip))
    }

    pub fn clear(&mut self, ip: IP) {
        self.arp_entries.clear();
    }

    pub fn add_arp_entry(&mut self, arp_entry: ARPEntry ) -> bool {
        let index = self.arp_entries.iter()
            .position(|entry| entry.ip_addr.eq(&arp_entry.ip_addr));

        if index.is_none(){
            self.arp_entries.push_back(arp_entry);
            return true;
        }
        if index.is_some() {
            self.arp_entries.remove(index.unwrap());
            self.arp_entries.push_back(arp_entry);
            return true;
        }

        false
    }

    pub fn update_from_arp_reply(&mut self, arp_hdr: ARPHeader, iif: &Interface) {
        assert!(arp_hdr.op_code == ARP_REPLY);
        let arp_entry = ARPEntry{
            ip_addr: arp_hdr.src_ip,
            mac_addr: arp_hdr.src_mac,
            oif_name: iif.get_if_name(),
            is_sane: false
        };
        self.add_arp_entry(arp_entry);
    }

    pub fn dump_arp_table(&self) {
        self.arp_entries.iter().map(|entry|{
            println!("IP : {}, MAC : {}, OIF = {}, Is Sane:{}",
                entry.ip_addr,
                entry.mac_addr,
                std::str::from_utf8(&entry.oif_name).unwrap(),
                entry.is_sane
            );
        });
    }
}

pub fn send_arp_broadcast_request(node: &Node, oif: &Interface, ip: IP) -> Result<()> {
    match node.get_matching_subnet_interface(ip) {
        None => {
            return Err(Error::ARPError(format!("Error : {} : \
            No eligible subnet for ARP resolution for Ip-address : {}", node.get_name()?, ip)));
        }
        Some(interface) => {
            match interface.get_ip_address() == ip {
                true => {
                    return Err(Error::ARPError(format!("Error : {} : \
                    Attempt to resolve ARP for local Ip-address : {}",
                                                       node.get_name()?, ip)));
                },
                false => {
                    let mut ethernet_header = EthernetHeader::default();
                    ethernet_header.set_des_mac(MAC([0xff,0xff,0xff,0xff,0xff,0xff]));
                    ethernet_header.set_src_mac(interface.get_mac_address());
                    ethernet_header.set_type(ARP_MSG);
                    
                    let arp_hdr = ARPHeader{
                        hw_type: 1,
                        proto_type: 0x0800,
                        hw_addr_len: 6,
                        proto_addr_type: 4,
                        op_code: ARP_BROAD_REQ,
                        src_mac: oif.get_mac_address(),
                        src_ip: oif.get_ip_address(),
                        des_mac: Default::default(),
                        des_ip: ip
                    };
                    ethernet_header.set_payload(arp_hdr.to_bytes());
                    interface.pkt_send_out(&ethernet_header.to_bytes())?;
                    Ok(())
                }
            }
        }
    }
}

pub fn send_arp_eply_msg(ethernet_bytes: &[u8], oif: &Interface) -> Result<()> {
    let ethernet_hdr_in = EthernetHeader::from_bytes(ethernet_bytes)?;
    let arp_hdr_in = ARPHeader::from_bytes(&ethernet_hdr_in.payload)?;

    let arp_hdr_reply = ARPHeader{
        hw_type: 1,
        proto_type: 0x0800,
        hw_addr_len: 6,
        proto_addr_type: 4,
        op_code: ARP_REPLY,
        src_mac: oif.get_mac_address(),
        src_ip: arp_hdr_in.src_ip,
        des_mac: arp_hdr_in.src_mac,
        des_ip: arp_hdr_in.src_ip,
    };

    let mut ethernet_hdr_reply = EthernetHeader::default();
    ethernet_hdr_reply.set_type(ARP_MSG);
    ethernet_hdr_reply.set_des_mac(arp_hdr_in.src_mac);
    ethernet_hdr_reply.set_src_mac(oif.get_mac_address());
    ethernet_hdr_reply.set_payload(arp_hdr_reply.to_bytes());

    oif.pkt_send_out(&ethernet_hdr_reply.to_bytes())
}
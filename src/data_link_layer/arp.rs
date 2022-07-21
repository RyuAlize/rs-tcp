use std::collections::LinkedList;
use std::fmt::{Display, Formatter};

use lazy_static::lazy_static;
use memoffset::offset_of;

use crate::error::{Error, Result};

use super::*;



#[derive(Debug)]
pub struct ARPHeader {
    /*1 for ethernet cable*/
    hw_type: u16,
    /*0x0800 for IPV4*/
    proto_type: u16,
    /*6 for MAC*/
    hw_addr_len: u8,
    /*4 for IPV4*/
    proto_addr_type: u8,
    /*req or reply*/
    op_code: u16,
    src_mac: MAC,
    src_ip: IP,
    des_mac: MAC,
    des_ip: IP,
}


impl ARPHeader {
    pub fn from_bytes(mut bytes: BytesMut) -> Result<Self> {
        Ok(Self {
            hw_type: bytes.get_u16(),
            proto_type: bytes.get_u16(),
            hw_addr_len: bytes.get_u8(),
            proto_addr_type: bytes.get_u8(),
            op_code: bytes.get_u16(),
            src_mac: MAC((&bytes.copy_to_bytes(6)[..]).try_into().unwrap()),
            src_ip: IP((&bytes.copy_to_bytes(4)[..]).try_into().unwrap()),
            des_mac: MAC((&bytes.copy_to_bytes(6)[..]).try_into().unwrap()),
            des_ip: IP((&bytes.copy_to_bytes(4)[..]).try_into().unwrap()),
        })
    }

    pub fn to_bytes(mut self) -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.hw_type.to_be_bytes());
        bytes.put_slice(&self.proto_type.to_be_bytes());
        bytes.put_slice(&self.hw_addr_len.to_be_bytes());
        bytes.put_slice(&self.proto_addr_type.to_be_bytes());
        bytes.put_slice(&self.op_code.to_be_bytes());
        bytes.put_slice(&self.src_mac.0);
        bytes.put_slice(&self.src_ip.0);
        bytes.put_slice(&self.des_mac.0);
        bytes.put_slice(&self.des_ip.0);
        bytes
    }

    #[inline]
    pub fn op_code(&self) -> u16 {
        self.op_code
    }
}

pub struct ARPPendingEntry {

    //arp_processing_fn:
}

#[derive(Debug)]
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

    pub fn delete_pending_entries(&mut self) {}

    pub fn add_pending_entry(&mut self, pkt: &[u8]) {}
}

pub struct ARPTable {
    arp_entries: LinkedList<ARPEntry>,
}

impl ARPTable {
    pub fn init() -> Self {
        Self {
            arp_entries: LinkedList::new(),
        }
    }

    pub fn lookup(&self, ip: IP) -> Option<&ARPEntry> {
        self.arp_entries.iter().find(|&entry| entry.ip_addr.eq(&ip))
    }

    pub fn clear(&mut self, ip: IP) {
        self.arp_entries.clear();
    }

    pub fn add_arp_entry(&mut self, arp_entry: ARPEntry) -> bool {
        let index = self.arp_entries.iter()
            .position(|entry| entry.ip_addr.eq(&arp_entry.ip_addr));

        if index.is_none() {
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

    pub fn update_from_arp_reply(&mut self, arp_hdr: &ARPHeader, iif: &Interface) {
        assert!(arp_hdr.op_code == ARP_REPLY);
        let arp_entry = ARPEntry {
            ip_addr: arp_hdr.src_ip,
            mac_addr: arp_hdr.src_mac,
            oif_name: iif.get_if_name().clone(),
            is_sane: false,
        };
        self.add_arp_entry(arp_entry);
    }

    pub fn dump(&self) {
        for entry in self.arp_entries.iter() {
            println!("IP : {}, MAC : {}, OIF = {}, Is Sane:{}",
                     entry.ip_addr,
                     entry.mac_addr,
                     std::str::from_utf8(&entry.oif_name).unwrap(),
                     entry.is_sane
            );
        }
    }
}

pub fn send_arp_broadcast_request(node: &Node, ip: IP) -> Result<()> {
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
                        src_mac: interface.get_mac_address(),
                        src_ip: interface.get_ip_address(),
                        des_mac: Default::default(),
                        des_ip: ip
                    };
                    ethernet_header.set_payload(arp_hdr.to_bytes().to_vec());

                    interface.pkt_send_out(&ethernet_header.to_bytes())
                }
            }
        }
    }
}

pub fn send_arp_reply_msg(ethernet_hdr_in: &EthernetHeader,
                          arp_hdr_in: &ARPHeader,
                          oif: &Interface) -> Result<()> {

    let arp_hdr_reply = ARPHeader{
        hw_type: 1,
        proto_type: 0x0800,
        hw_addr_len: 6,
        proto_addr_type: 4,
        op_code: ARP_REPLY,
        src_mac: oif.get_mac_address(),
        src_ip: oif.get_ip_address(),
        des_mac: arp_hdr_in.src_mac,
        des_ip: arp_hdr_in.src_ip,
    };

    let mut ethernet_hdr_reply = EthernetHeader::default();
    ethernet_hdr_reply.set_type(ARP_MSG);
    ethernet_hdr_reply.set_des_mac(arp_hdr_in.src_mac);
    ethernet_hdr_reply.set_src_mac(oif.get_mac_address());
    ethernet_hdr_reply.set_payload(arp_hdr_reply.to_bytes().to_vec());
    oif.pkt_send_out(&ethernet_hdr_reply.to_bytes())
}

pub fn process_arp_broadcast_request(node: &Node,
                                     iif: &Interface,
                                     ethernet_hdr_in: &EthernetHeader,
                                     arp_hdr_in: &ARPHeader) -> Result<()> {
    println!("ARP Broadcast msg recvd on interface {} of node {}",
             iif.get_if_name_str()?,
             iif.get_att_node()?.get_name()?);

    if !iif.get_ip_address().eq(&arp_hdr_in.des_ip) {
        println!("{} : ARP Broadcast req msg dropped, Dst IP address {} \
            did not match with interface ip : {}",
            node.get_name()?,
            arp_hdr_in.des_ip,
            iif.get_ip_address());
        return Ok(());
    }
    send_arp_reply_msg(&ethernet_hdr_in, &arp_hdr_in, iif)
}

pub fn process_arp_reply_msg(node: &mut Node,
                             iif: &Interface,
                             ethernet_hdr_in: &EthernetHeader,
                             arp_hdr_in: &ARPHeader) -> Result<()> {
    println!("ARP reply msg recvd on interface {} of node {}",
             iif.get_if_name_str()?,
             iif.get_att_node()?.get_name()?);

    let mut arp_table = node.get_arp_table();
    arp_table.update_from_arp_reply(arp_hdr_in, iif);

    Ok(())
}
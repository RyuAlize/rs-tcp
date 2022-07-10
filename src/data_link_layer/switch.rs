use std::cell::RefCell;
use std::collections::linked_list::LinkedList;

use crate::config::*;

use super::*;

pub struct MACTableEntry {
    mac_addr: MAC,
    oif_name: [u8; IF_NAME_SIZE],
}

impl PartialEq for MACTableEntry {
    fn eq(&self, other: &Self) -> bool {
        self.mac_addr.eq(&other.mac_addr) &&
            self.oif_name.eq(&other.oif_name)
    }
}

pub struct MACTable {
    mac_entries: LinkedList<MACTableEntry>,
}


impl MACTable {
    pub fn init() -> Self {
        Self { mac_entries: LinkedList::new() }
    }

    pub fn lookup(&self, mac: &MAC) -> Option<&MACTableEntry> {
        self.mac_entries.iter().find(|&entry| entry.mac_addr.eq(mac))
    }

    pub fn add(&mut self, new_entry: MACTableEntry) {
        if let Some(index) = self.mac_entries.iter()
            .position(|entry| entry.mac_addr.eq(&new_entry.mac_addr)) {
            self.mac_entries.remove(index);
        }
        self.mac_entries.push_back(new_entry);
    }

    pub fn delete(&mut self, mac: &MAC) {
        if let Some(index) = self.mac_entries.iter()
            .position(|entry| entry.mac_addr.eq(mac)) {
            self.mac_entries.remove(index);
        }
    }

    pub fn dump(&self) {
        for entry in &self.mac_entries {
            println!("Interface{}, Mac:{}",  std::str::from_utf8(&entry.oif_name).unwrap(), entry.mac_addr)
        }
    }
}


pub fn switch_perform_mac_learning(node: &mut Node,
                                   src_mac: MAC,
                                   if_name: [u8; IF_NAME_SIZE]) -> Result<()> {
    let new_entry = MACTableEntry { mac_addr: src_mac, oif_name: if_name };
    node.get_mac_lable().add(new_entry);
    Ok(())
}

pub fn switch_forward_frame(node: &Node, pkt: &[u8], recv_intf: &Interface) -> Result<()> {
    let ethernet_hdr = EthernetHeader::from_bytes(BytesMut::from(pkt))?;
    if ethernet_hdr.is_broadcast_mac() {
        return node.send_pkt_flood(pkt, recv_intf);
    } else if let Some(entry) = node.get_mac_lable().lookup(&ethernet_hdr.dst_mac) {
        let interface = node.get_node_if_by_name(&entry.oif_name);
        if !interface.is_null() {
            unsafe {
                (*interface).pkt_send_out(pkt)?;
            }
        }
    } else {
        node.send_pkt_flood(pkt, recv_intf)?;
    }

    Ok(())
}

pub fn switch_recv_frame(interface: &Interface, pkt: &[u8]) -> Result<()> {
    let node = interface.get_att_node()?;
    let ethernet_hdr = EthernetHeader::from_bytes(BytesMut::from(pkt))?;
    switch_perform_mac_learning(node, ethernet_hdr.src_mac, interface.get_if_name())?;
    switch_forward_frame(node, pkt, interface)
}


use std::fmt::{Display, Formatter};
use memoffset::offset_of;
use crate::topograph::{
    glthread::*,
    net::*,
    graph::*,
};
use crate::data_link_layer::EthernetHeader;

use crate::error::{Result, Error};

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

pub struct ARPPendingEntry {
    arp_pending_entry_glue: GLThread,
    //arp_processing_fn:
}

pub struct ARPEntry {
    ip_addr: IP,
    mac_addr: MAC,
    oif_name: [u8; IF_NAME_SIZE],
    arp_glue: GLThread,
    is_sane: bool,
    arg_pending_list: GLThread,
}

impl ARPEntry {
    pub fn delete(mut self) {
        unsafe{
            remove_glthread(&self.arp_glue as *const _ as *mut GLThread);
        }
        self.delete_pending_entries();
    }

    pub fn delete_pending_entries(&mut self) {
        while ! self.arg_pending_list.right.is_null() {
            unsafe {
                remove_glthread(self.arg_pending_list.right);
            }
        }
    }

    pub fn add_pending_entry(&mut self, pkt: &[u8]) {

    }
}

pub struct ARPTable {
    arp_entries: GLThread,
}

impl ARPTable {
    pub fn init() -> Self {
        Self{
            arp_entries: init_glthread(),
        }
    }

    pub fn lookup(&self, ip: IP) -> Option<&ARPEntry> {
        let mut curr = self.arp_entries.right;
        while !curr.is_null() {
           unsafe {
               let arp_entry = arp_glue_to_arp_entry(curr);
                if (*arp_entry).ip_addr == ip {
                    return Some(&*arp_entry);
                }
           }
        }
        None
    }

    pub fn clear(&mut self) {

    }

}

pub fn send_arp_broadcast_request(node: &Node, interface: &Interface, ip: IP) -> Result<()> {
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


                    Ok(())
                }
            }
        }
    }
}



#[inline]
pub unsafe fn arp_glue_to_arp_entry(glthread: *mut GLThread) -> *mut ARPEntry {
    let offset = offset_of!(ARPEntry, arp_glue);
    let arp_entry_addr = (glthread as usize) - offset;
    arp_entry_addr as *mut ARPEntry
}
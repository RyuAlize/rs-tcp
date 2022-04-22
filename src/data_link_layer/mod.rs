mod arp;
use crate::topograph::graph::{Interface, Node};
use crate::topograph::net::{InterfaceMode, MAC};

#[derive(Default)]
pub struct EthernetHeader {
    dst_mac: MAC,
    src_mac: MAC,
    eth_type: u16,
    payload: Vec<u8>,
    FCS: u32,
}

impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self{
        todo!()
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

    #[inline]
    pub fn is_broadcast_mac(&self) -> bool {
        self.dst_mac.eq(&MAC([0xff,0xff,0xff,0xff,0xff,0xff]))
    }
}

pub fn l2_frame_recv_qualify_on_interface(interface: &Interface,
                                          ethernet_hdr: &EthernetHeader,
                                          output_vlan_id: usize) -> bool {
    let interface_mode = interface.l2_mode();

    /* If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/
    if !interface.is_l3_mode(){
        return false;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if interface.is_l3_mode() && interface.get_mac_address().eq(&ethernet_hdr.dst_mac){
        return true;
    }

    /*If interface is working in L3 mode, then accept the frame with
    * broadcast MAC*/
    if interface.is_l3_mode() && ethernet_hdr.is_broadcast_mac() {
        return true;
    }

    false
}

pub fn layer2_frame_recv(node: &Node, interface: &Interface, pkt: &[u8]) {

}




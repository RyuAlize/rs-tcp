pub mod arp;
use nom::{IResult, Err, bytes::complete::take};
use nom::character::complete::u32;

use crate::error::{Error, Result};
use crate::topograph::{
    net_util::*,
    graph::*,
};
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
        bytes.extend_from_slice(& self.eth_type.to_be_bytes());
        bytes.extend_from_slice(& self.payload);
        bytes.extend_from_slice(& self.FCS.to_be_bytes());

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

fn take_payload(len: usize, input:&[u8]) -> IResult<&[u8], &[u8]> {
    take(len)(input)
}



impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>{

        let len = bytes.len();
        let (bytes, dst_mac) = take6(bytes).unwrap();
        let (bytes, src_mac) = take6(bytes).unwrap();
        let (bytes, eth_type) = take2(bytes).unwrap();
        let (bytes, payload) =take_payload(len-18, bytes).unwrap();
        let (bytes, FCS) = take4(bytes).unwrap();
        let hdr = EthernetHeader {
            dst_mac: MAC(dst_mac.try_into().unwrap()),
            src_mac:MAC(src_mac.try_into().unwrap()),
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



#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn test_ethernet_hdr() -> Result<()>{
        let ethernet_hdr = EthernetHeader{
            dst_mac: MAC([1,2,3,4,5,6]),
            src_mac: MAC([2,3,4,5,6,7]),
            eth_type: 11,
            payload: vec![b'a',b'a',b'a',b'a',b'a',b'a'],
            FCS: 12
        };
        let bytes = ethernet_hdr.to_bytes();
        println!("{:?}", bytes);
        let hdr = EthernetHeader::from_bytes(&bytes)?;
        println!("{:?}", hdr);
        Ok(())
    }
}
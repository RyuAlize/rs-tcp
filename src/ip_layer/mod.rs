mod ip;

use crate::topograph::graph::{Node, Interface};
use crate::config::*;



pub fn promote_pkt_to_layer3(node: &mut Node,
                             interface: &Interface,
                             pkt: &[u8],
                             protocol_number: u16) {
    match protocol_number {
        ETH_IP | IP_IN_IP => layer3_ip_pkt_recv_from_bottom(node, interface, pkt),
        _ =>{}
    }
}

pub fn layer3_ip_pkt_recv_from_bottom(node: &mut Node, interface: &Interface, pkt: &[u8]) {

}

pub fn layer3_pkt_recv_from_top() {

}
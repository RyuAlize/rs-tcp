pub const TOPOLOGY_NAME_SIZE: usize = 16;
pub const NODE_NAME_SIZE: usize = 16;
pub const IF_NAME_SIZE: usize = 16;
pub const MAX_INTF_PER_NODE: usize = 10;
pub const MAX_PACKET_BUFFER_SIZE: usize = 1024;

pub const ARP_BROAD_REQ: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const ARP_MSG: u16 = 806;
pub const ETH_IP: u16 = 0x0800;
pub const IP_IN_IP: u16 = 4;
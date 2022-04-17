use std::fmt::{Display, Formatter};

const MAX_VLAN_MEMBERHIP: usize = 10;

pub struct IPV4([u8;4]);
pub struct IPV6([u8;16]);
pub struct IP(pub [u8;4]);
pub struct MAC(pub [u8;6]);

impl Display for IP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}",
               self.0[0],self.0[1],self.0[2],self.0[3])
    }
}

impl Display for MAC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               self.0[0],self.0[1],self.0[2],self.0[3],self.0[4],self.0[5])
    }
}

enum InterfaceMode{
    ACCESS,
    TRUNK,
    UNKNOWN,
}

impl Display for InterfaceMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ACCESS => {write!(f, "ACCESS")},
            Self::TRUNK => {write!(f, "TRUNK")},
            Self::UNKNOWN => {write!(f, "L2_MODE_UNKNWON")},
        }
    }
}

pub struct ARPTable;
pub struct MACTable;
pub struct RTTable;

#[repr(C)]
pub struct NetWorkNodeProperty {
    flags: usize,
    // L2 Data link layer properties
    arp_table: ARPTable,
    mac_table: MACTable,
    rt_table: RTTable,
    // L3 network layer porperties
    is_lb_addr_config: bool,
    loopback_addr: IP,
}

impl NetWorkNodeProperty {
    pub fn init() -> NetWorkNodeProperty{
        NetWorkNodeProperty{
            flags: 0,
            arp_table: ARPTable,
            mac_table: MACTable,
            rt_table: RTTable,
            is_lb_addr_config: false,
            loopback_addr: IP([0u8;4]),
        }
    }

    #[inline]
    pub fn get_loopback_address(&self) -> &IP {
        &self.loopback_addr
    }

    #[inline]
    pub fn get_flags(&self) -> usize {
        self.flags
    }

    #[inline]
    pub fn set_loopback_address(&mut self, ip: IP) {
        self.loopback_addr = ip;
    }

    #[inline]
    pub fn lb_addr_config(&mut self, flag: bool) {
        self.is_lb_addr_config = flag;
    }

    #[inline]
    pub fn dump(&self) {
        println!("\t node flags : {}", self.flags);
        if self.is_lb_addr_config {
            println!("\t lo addr : {}/32", self.loopback_addr);
        }
    }
}

#[repr(C)]
pub struct InterfaceProperty {
    // L2 Data link layer properties
    mac_addr: MAC,
    interface_mode: InterfaceMode,
    vlans: [usize; MAX_VLAN_MEMBERHIP],
    is_ipaddr_config_backup: bool,
    //L3 network layer properties
    is_ipaddr_config: bool,
    ip_addr: IP,
    mask: u8,
}

impl InterfaceProperty {
    pub fn init() -> InterfaceProperty {
        InterfaceProperty{
            mac_addr: MAC([0u8; 6]),
            interface_mode: InterfaceMode::UNKNOWN,
            vlans: [0; MAX_VLAN_MEMBERHIP],
            is_ipaddr_config_backup: false,
            is_ipaddr_config: false,
            ip_addr: IP([0u8;4]),
            mask: 0,
        }
    }

    #[inline]
    pub fn get_mac(&self) -> &MAC {
        &self.mac_addr
    }

    #[inline]
    pub fn get_ip(&self) -> &IP {
        &self.ip_addr
    }

    #[inline]
    pub fn interface_mode(&self) -> &InterfaceMode {
        &self.interface_mode
    }

    #[inline]
    pub fn is_l3_mode(&self) -> bool {
        self.is_ipaddr_config
    }

    #[inline]
    pub fn set_interface_ip_address(&mut self, ip: IP, mask: u8){
        self.ip_addr = ip;
        self.mask = mask;
    }

    #[inline]
    pub fn set_interface_mac_address(&mut self, mac: MAC) {
        self.mac_addr = mac;
    }

    #[inline]
    pub fn ipadd_config(&mut self, flag:bool) {
        self.is_ipaddr_config = flag;
    }

    #[inline]
    pub fn dump(&self) {
        match self.is_ipaddr_config {
            true => {
                println!("\t IP Addr = {}/{}", self.ip_addr, self.mask);
                println!("\t MAC: {}", self.mac_addr);
            },
            false => {
                println!("\t l2 mode = {}", self.interface_mode);
                println!("\t vlan membership: ");
                for i in 0.. MAX_VLAN_MEMBERHIP {
                    print!("{} ", self.vlans[i]);
                }
                println!(" ")
            }
        }
    }
}


pub fn hash_code(bytes: &[u8], size: usize) -> usize {
    let mut value = 0;
    for i in 0..size {
        value += bytes[i] as usize;
    }
    value
}

pub fn hash_code_to_mac(value: usize) -> MAC {
    let b0 : u8 = ((value >> 40) & 0xff) as u8;
    let b1 : u8 = ((value >> 32) & 0xff) as u8;
    let b2 : u8 = ((value >> 24) & 0xff) as u8;
    let b3 : u8 = ((value >> 16) & 0xff) as u8;
    let b4 : u8 = ((value >> 8) & 0xff) as u8;
    let b5 : u8 = (value & 0xff) as u8;

    MAC([b0,b1,b2,b3,b4,b5])
}


#[cfg(test)]
mod test {
    #[test]
    fn test_ip() {

    }
}
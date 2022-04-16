

const MAX_VLAN_MEMBERHIP: usize = 10;

pub struct IPV4([u8;4]);
pub struct IPV6([u8;16]);
pub struct IP([u8;16]);
pub struct MAC([u8;6]);

pub struct ARPTable;
pub struct MACTable;
pub struct RTTable;

pub struct NetWorkNodeProperty {
    flags: usize,
    // L2 Data link layer properties
    arp_table: ARPTable,
    mac_table: MACTable,
    rt_table: RTTable,
    // L3 network layer porperties
    is_lb_addr_config: bool,
    ip_addr: IP,
}

impl NetWorkNodeProperty {
    pub fn init() -> NetWorkNodeProperty{
        NetWorkNodeProperty{
            flags: 0,
            arp_table: ARPTable,
            mac_table: MACTable,
            rt_table: RTTable,
            is_lb_addr_config: false,
            ip_addr: IP([0u8;16]),
        }
    }

    #[inline]
    pub fn get_ip(&self) -> &IP {
        &self.ip_addr
    }

    #[inline]
    pub fn get_flags(&self) -> usize {
        self.flags
    }

    #[inline]
    pub fn set_loopback_address(&mut self, ip: IP) {

    }
}

enum InterfaceMode{
    ACCESS,
    TRUNK,
    UNKNOWN,
}

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
            ip_addr: IP([0u8;16]),
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
    pub fn set_interface_ip_address(&mut self, ip: IP, mask: usize){

    }

    #[inline]
    pub fn unset_interface_ip_address(&mut self) {

    }
}


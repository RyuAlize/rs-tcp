use std::collections::LinkedList;
use crate::config::IF_NAME_SIZE;
use crate::topograph::net_util::IP;
use crate::topograph::net_util::apply_mask;

pub struct IPHeader {
    ///version number, always 4 for IPv4 protocol
    version: u8,
    ///length of IP hdr, in 32-bit words unit
    ihl: u8,
    ///type of service
    tos: u8,
    ///length of hdr + ip_hdr payload
    total_length: u16,

    ///Fragmentation related
    id: u16,
    unused_flags: u32,
    DF_flag: u32,
    more_flag: u32,
    frag_offset: u16,

    ///time to live
    tti: u8,
    protocol: u8,
    checksum:u16,
    src_ip: IP,
    dst_ip: IP,
}

impl IPHeader {
    pub fn new(src_ip: IP, dst_ip: IP) -> Self {
        Self {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 0,
            id: 0,
            unused_flags: 0,
            DF_flag: 1,
            more_flag: 0,
            frag_offset: 0,
            tti: 64,
            protocol: 0,
            checksum: 0,
            src_ip,
            dst_ip
        }
    }

    pub fn to_bytes(&self) {

    }

    pub fn from_bytes() {

    }
}


pub struct RoutEntry {
    dest: IP,
    mask: u8,
    is_direct: bool,
    gw_ip: Option<IP>,
    oif: [u8; IF_NAME_SIZE]
}


pub struct RTTable {
    rout_list: LinkedList<RoutEntry>
}

impl RTTable {
    pub fn new() -> Self{
        Self{rout_list: LinkedList::new()}
    }

    pub fn lookup(&self, dest: &IP, mask: u8) -> Option<&RoutEntry> {
        self.rout_list.iter().find(|&entry| entry.dest.eq(dest) && entry.mask == mask)
    }

    /// Look up with longest prefix match
    pub fn lookup_with_lpm(&self, dest: &IP) -> Option<&RoutEntry> {
        let mut longest_mask = 0;
        let mut default_route = None;
        let mut lpm_route = None;
        for entry in &self.rout_list {
            let subnet = IP(apply_mask(dest.clone(), entry.mask));
            if entry.dest.eq(&IP([0,0,0,0])) && entry.mask == 0{
                default_route = Some(entry);
            }
            else if entry.dest.eq(&subnet) && entry.mask > longest_mask{
                longest_mask = entry.mask;
                lpm_route = Some(entry);
            }
        }
        if lpm_route.is_some() {
            lpm_route
        }
        else{
            default_route
        }
    }

    pub fn add_rout_entry(&mut self, dest: IP, mask: u8, gw: Option<IP>, oif: [u8; IF_NAME_SIZE]) {
        let masked_dest = IP(apply_mask(dest, mask));
        if self.lookup_with_lpm(&masked_dest).is_some() {return;}
        let new_entry =  RoutEntry{
            dest: masked_dest,
            mask,
            is_direct: match gw {Some(_) => false, None => true},
            gw_ip: gw,
            oif
        };
        self.rout_list.push_back(new_entry);

    }

    pub fn clear(&mut self) {
        self.rout_list.clear();
    }

    pub fn dump_table(&self) {
        for entry in & self.rout_list {
            match entry.gw_ip {
                Some(gw) => {
                    println!("\t{}/{} {} {}", entry.dest, entry.mask, gw,
                             std::str::from_utf8(&entry.oif).unwrap());
                },
                None => {println!("\t{}/{} Na Na", entry.dest, entry.mask);}
            }
        }
    }


}



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
    More_flag: u32,
    frag_offset: u16,

    ///time to live
    tti: u8,
    protocol: u8,
    checksum:u16,
    src_ip: u32,
    dst_ip: u32,
}
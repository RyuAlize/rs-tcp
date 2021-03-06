use std::alloc::{alloc, Layout};
use std::cell::{RefCell, RefMut};
use std::fmt::format;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::thread;
use std::time::Duration;

use memoffset::offset_of;
use mio::{Events, Interest, net::UdpSocket, Poll, Token};

use crate::config::*;
use crate::data_link_layer::arp::ARPTable;
use crate::data_link_layer::layer2_frame_recv;
use crate::data_link_layer::switch::MACTable;
use crate::error::{Error, Result};
use crate::topograph::glthread::{*};
use crate::topograph::net_util::{*};

#[repr(C)]
pub struct Graph {
    topology_name: [u8; TOPOLOGY_NAME_SIZE],
    node_list: GLThread,
}

impl Graph {
    pub fn new(topology_name: &[u8; TOPOLOGY_NAME_SIZE]) -> Self {
/*        let layout = Layout::new::<Graph>();
        unsafe {
            let p = alloc(layout) as *mut Self;
            let graph = &mut *p;
            std::ptr::write(&mut graph.topology_name, *topology_name);
            std::ptr::write(&mut graph.node_list,
                            GLThread{ left: std::ptr::null_mut(), right: std::ptr::null_mut() });
            p
        }*/
        Self{
            topology_name: *topology_name,
            node_list: GLThread{ left: std::ptr::null_mut(), right: std::ptr::null_mut() }
        }
    }

    pub fn add_node(&mut self, node_name: &[u8; NODE_NAME_SIZE]) -> *mut Node{
        let new_node = Node::new(node_name);
        unsafe {
            let curr_glthread = &self.node_list as *const _ as *mut GLThread;
            let new_glthread = &(*new_node).graph_glue as *const _ as *mut GLThread;
            glthread_add_next(curr_glthread, new_glthread);
        }
        new_node
    }

    pub fn insert_link(&self,
                       node_src: *mut Node,
                       node_des: *mut Node,
                       if_src_name: &[u8; IF_NAME_SIZE],
                       if_des_name: &[u8; IF_NAME_SIZE],
                       cost: usize)
    {
        let boxed_if_src = Box::new(Interface{
            if_name: *if_src_name,
            att_node: node_src,
            link: std::ptr::null_mut(),
            intf_props: InterfaceProperty::init(),
        });
        let if_src =  Box::into_raw(boxed_if_src);
        let boxed_if_des = Box::new(Interface{
            if_name: *if_des_name,
            att_node: node_des,
            link: std::ptr::null_mut(),
            intf_props: InterfaceProperty::init(),
        });
        let if_des = Box::into_raw(boxed_if_des);
        let boxed_link = Box::new(Link {
            if_src,
            if_des,
            cost,
        });
        let link = Box::into_raw(boxed_link);
        unsafe {
            (*if_src).link = link;
            (*if_des).link = link;
            (*if_src).set_mac_address();
            (*if_des).set_mac_address();
            if let Some(index) = (*node_src).get_node_intf_available_slot() {
                (*node_src).interfaces[index] = if_src;
            }
            if let Some(index) = (*node_des).get_node_intf_available_slot() {
                (*node_des).interfaces[index] = if_des;
            }
        }
    }

    #[inline]
    pub fn get_node_by_node_name(&self, node_name: &[u8; NODE_NAME_SIZE]) -> *mut Node {
        let base = &self.node_list.right as *const _ as *mut GLThread;

        while !base.is_null() {
            unsafe {
                let node = graph_glue_to_node(base);
                if (*node).node_name == *node_name {
                    return node;
                }
            }
        }
        std::ptr::null_mut()
    }

    pub fn start_pkt_receiver_thread(&self) {
        let base = AtomicPtr::from(self.node_list.right);
        thread::spawn(move || {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(128);
            let registry = poll.registry();
            let mut node_list = vec![];
            let mut glthread = base.into_inner();
            unsafe {
                let mut i = 0;
                while !glthread.is_null() {
                    let node = graph_glue_to_node(glthread);
                    if (*node).udp_sock.is_some() {
                        let socket = &mut *(*node).udp_sock.as_mut().unwrap();
                        node_list.push(node);
                        registry.register(socket,
                                          Token(i),
                                          Interest::READABLE).unwrap();
                        i += 1;
                    }
                    glthread = (*glthread).right;
                }
            }
            loop {
                poll.poll(&mut events, None);
                for event in events.iter() {
                    let mut buf = vec![0; 1024];
                    unsafe {
                        if let Ok(size) = (*node_list[event.token().0]).udp_sock.as_ref().unwrap().recv(&mut buf) {
                            (*node_list[event.token().0]).pkt_receive(&buf, size);
                            let socket = (*node_list[event.token().0]).udp_sock.as_mut().unwrap();
                            poll.registry().reregister(socket, event.token(), Interest::READABLE);
                        }
                    }
                }
            }
        });
    }

    pub fn dump_graph(&self) {
        let mut base = self.node_list.right;
        while !base.is_null() {
            unsafe {
                let node = graph_glue_to_node(base);
                (*node).dump_node();
                base = (*base).right;
            }
        }
    }
}

#[repr(C)]
pub struct Interface {
    if_name: [u8; IF_NAME_SIZE],
    att_node: *mut Node,
    link: *mut Link,
    intf_props: InterfaceProperty,
}

impl Interface {
    #[inline]
    pub fn get_nbr_node(&self) -> Result<&Node> {
        unsafe {
            if !self.link.is_null() {
                match std::ptr::eq(self, (*self.link).if_src) {
                    true => { return Ok(&*(*(*self.link).if_des).att_node); }
                    false => { return Ok(&*(*(*self.link).if_src).att_node); }
                }
            }
        }
        Err(Error::NeighborNodeNotFound)
    }

    pub fn get_att_node(&self) -> Result<&mut Node> {
        if self.att_node.is_null() {
            return Err(Error::InterfaceNotAttNode);
        } else {
            unsafe { return Ok(&mut *self.att_node); }
        }
    }

    pub fn get_property(&mut self) -> &mut InterfaceProperty{
        &mut self.intf_props
    }

    #[inline]
    pub fn get_ip_address(&self) -> IP {
        self.intf_props.get_ip()
    }

    #[inline]
    pub fn get_mac_address(&self) -> MAC {
        self.intf_props.get_mac()
    }

    #[inline]
    pub fn get_if_name(&self) -> [u8; IF_NAME_SIZE] {
        self.if_name
    }

    pub fn get_if_name_str(&self) -> Result<String> {
        let name = std::str::from_utf8(&self.if_name)?;
        Ok(name.to_owned())
    }

    #[inline]
    pub fn is_l3_mode(&self) -> bool {
        self.intf_props.is_l3_mode()
    }

    #[inline]
    pub fn l2_mode(&self) -> &InterfaceMode {
        self.intf_props.get_interface_mode()
    }

    pub fn set_mac_address(&mut self) {
        if self.att_node.is_null() { return; }
        let mut hash_code_val = 0;
        unsafe {
            hash_code_val = hash_code(&(*self.att_node).node_name, NODE_NAME_SIZE);
            hash_code_val *= hash_code(&self.if_name, IF_NAME_SIZE);
        }
        self.intf_props.set_interface_mac_address(hash_code_to_mac(hash_code_val));
    }

    pub fn set_interface_mod(&mut self, mode: InterfaceMode) {
        self.intf_props.set_interface_mod(mode);
    }

    pub fn set_ip_address(&mut self, ip: IP, mask: u8) {
        self.intf_props.set_interface_ip_address(ip, mask);
        self.intf_props.set_ipadd_config(true);
    }

    pub fn pkt_send_out(&self, data: &[u8]) -> Result<()> {
        unsafe {
            let nbr_node = self.get_nbr_node()?;
            let des_port_number = nbr_node.udp_port_number;
            let other_interface = match std::ptr::eq(self, (*self.link).if_des) {
                true => (*self.link).if_src,
                false => (*self.link).if_des,
            };
            let mut bytes = (*other_interface).if_name.clone().to_vec();
            bytes.extend(data);
            let sock = UdpSocket::bind("127.0.0.1:0".parse()?)?;
            sock.send_to(&bytes, format!("127.0.0.1:{}", des_port_number).parse()?)?;
        }
        Ok(())
    }
}

#[repr(C)]
pub struct Link {
    if_src: *mut Interface,
    if_des: *mut Interface,
    cost: usize,
}

#[repr(C)]
pub struct Node {
    node_name: [u8; NODE_NAME_SIZE],
    interfaces: [*mut Interface; MAX_INTF_PER_NODE],
    graph_glue: GLThread,
    udp_port_number: usize,
    udp_sock: Option<UdpSocket>,
    node_proprs: NetWorkNodeProperty,
}

impl Node{
    pub  fn new(node_name: &[u8; NODE_NAME_SIZE]) -> *mut Self {
        unsafe{
            let layout = Layout::new::<Node>();
            let p = alloc(layout) as *mut Self;
            let node = &mut *p;
            std::ptr::write(&mut node.node_name, *node_name);
            std::ptr::write(&mut node.interfaces, [std::ptr::null_mut(); MAX_INTF_PER_NODE]);
            std::ptr::write(&mut node.graph_glue,
                            GLThread { left: std::ptr::null_mut(), right: std::ptr::null_mut() });
            std::ptr::write(&mut node.udp_port_number, 0);
            std::ptr::write(&mut node.udp_sock, None);
            std::ptr::write(&mut node.node_proprs, NetWorkNodeProperty::init());
            p
        }
    }
    #[inline]
    pub fn get_node_intf_available_slot(&self) -> Option<usize> {
        self.interfaces.iter().position(|f| f.is_null())
    }

    #[inline]
    pub fn get_name(&self) -> Result<String> {
        let name = std::str::from_utf8(&self.node_name)?;
        Ok(name.to_owned())
    }

    #[inline]
    pub fn get_node_if_by_name(&self, if_name: &[u8; IF_NAME_SIZE]) -> *mut Interface {
        for interface in self.interfaces {
            if !interface.is_null() {
                unsafe {
                    if (*interface).if_name == *if_name {
                        return interface;
                    }
                }
            }
        }
        std::ptr::null_mut()
    }

    pub fn dump_node(&self) {
        println!("Node name = {}", std::str::from_utf8(&self.node_name).unwrap());
        self.node_proprs.dump();
        unsafe {
            for i in 0..MAX_INTF_PER_NODE {
                if self.interfaces[i].is_null() { break; }
                let intf = self.interfaces[i];
                println!("Interface Name = {}\n\tNbr Node {}, Local Node : {}, cost = {}",
                         std::str::from_utf8(&(*intf).if_name).unwrap(),
                         std::str::from_utf8(&(*get_nbr_node(intf)).node_name).unwrap(),
                         std::str::from_utf8(&(*(*intf).att_node).node_name).unwrap(),
                         (*(*intf).link).cost);
                (*intf).intf_props.dump();
            }
        }
    }

    #[inline]
    pub fn get_arp_table(&self) -> RefMut<ARPTable> {
        self.node_proprs.get_arp_table()
    }

    #[inline]
    pub fn get_mac_lable(&self) -> RefMut<MACTable> {
        self.node_proprs.get_mac_table()
    }
    #[inline]
    pub fn set_loopback_address(&mut self, ip: IP) {
        self.node_proprs.set_loopback_address(ip);
        self.node_proprs.lb_addr_config(true);
    }

    pub fn set_intf_ip_address(&mut self,  if_name: &[u8; IF_NAME_SIZE], ip: IP, mask: u8) {
        let interface = self.get_node_if_by_name(if_name);
        unsafe {
            (*interface).set_ip_address(ip, mask);
        }
    }

    pub fn set_l2_mode(&mut self, if_name: &[u8; IF_NAME_SIZE], mode: InterfaceMode) -> Result<()> {
        unsafe {
            let intf = self.get_node_if_by_name(if_name);
            if !intf.is_null() {
                if (*intf).is_l3_mode() {
                    return Err(Error::InterfaceModeError(
                        format!("Interface {} is on l3 mode.", (*intf).get_if_name_str()?)));
                }
                (*intf).get_property().set_interface_mod(mode);
            } else {
                return Err(Error::InterfaceNotFound);
            }
        }
        Ok(())
    }

    pub fn set_interfaces_mode(&self, mode: InterfaceMode) {
        for intf in self.interfaces {
            if intf.is_null() {break;}
            unsafe{
                (*intf).set_interface_mod(mode);
            }
        }
    }

    pub fn get_matching_subnet_interface<'i>(&'i self, ip: IP) -> Option<&'i Interface> {
        for i in 0..MAX_INTF_PER_NODE {
            let interface = self.interfaces[i];
            if interface.is_null() { break; }

            unsafe {
                if !(*interface).intf_props.is_l3_mode() { continue; }
                let mask = (*interface).intf_props.get_mask();
                let network_number = apply_mask(ip, mask);
                if network_number == apply_mask((*interface).intf_props.get_ip(), mask) {
                    return Some(&*interface);
                }
            }
        }
        None
    }

    pub fn init_udp_sock(&mut self, udp_port_number: usize) -> Result<()> {
        self.udp_port_number = udp_port_number;
        let addr = format!("{}:{}", self.node_proprs.get_loopback_address(),
                           udp_port_number);
        let udp_sock = UdpSocket::bind(addr.parse()?)?;
        self.udp_sock = Some(udp_sock);
        Ok(())
    }

    pub fn send_pkt_out(&self, if_name:&[u8; IF_NAME_SIZE], pkt_data: &[u8]) -> Result<()> {
        unsafe{
            let index = self.interfaces.into_iter()
                .position(|intf| (*intf).get_if_name().eq(if_name));
            if index.is_some() {
                (*self.interfaces[index.unwrap()]).pkt_send_out(pkt_data)?;
            }
        }
        Ok(())
    }

    pub fn send_pkt_flood(&self, pkt_data: &[u8], exempted_intf: &Interface) -> Result<()> {
        for i in 0..MAX_INTF_PER_NODE {
            if self.interfaces[i].is_null() { break; }
            unsafe {
                if std::ptr::eq(self.interfaces[i], exempted_intf) { continue; }
                (*self.interfaces[i]).pkt_send_out(pkt_data)?;
            }
        }
        Ok(())
    }


    pub fn pkt_receive(&mut self, buf: &[u8], size: usize) -> Result<()> {
        assert!(size > IF_NAME_SIZE);
        let mut if_name = [0u8; IF_NAME_SIZE];
        for (i, b) in buf.iter().take(IF_NAME_SIZE).enumerate() {
            if_name[i] = b.to_owned();
        }

        let interface = self.get_node_if_by_name(&if_name);
        if !interface.is_null() {
            let data = buf[IF_NAME_SIZE..size].to_owned();
            unsafe {
                layer2_frame_recv(self, &*interface, &data)?;
            }
        }

        Ok(())
    }
}

#[inline]
pub unsafe fn get_nbr_node(interface: *mut Interface) -> *mut Node {
    if !(*interface).link.is_null() {
        match (*(*interface).link).if_src == interface {
            true => { return (*(*(*interface).link).if_des).att_node; }
            false => { return (*(*(*interface).link).if_src).att_node; }
        }
    }
    std::ptr::null_mut()
}

#[inline]
pub unsafe fn graph_glue_to_node(glthread: *mut GLThread) -> *mut Node {
    let offset = offset_of!(Node, graph_glue);
    let node_addr = (glthread as usize) - offset;
    node_addr as *mut Node
}


#[cfg(test)]
mod test {
    use std::borrow::{Borrow, BorrowMut};
    use std::thread::sleep;

    use mio::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn test_graph_glue_to_node() {
        let name = b"testtesttestestt";
        let node = Node::new(name);
        unsafe {
            let gp = &(*node).graph_glue as *const _ as *mut GLThread;
            let res = graph_glue_to_node(gp);
            assert_eq!(*name, (*res).node_name);
        }
    }

    #[test]
    fn test_graph()-> Result<()> {
        let topology_anme = b"###test_graph###";

        let mut graph = Graph::new(topology_anme);
        let node1 = graph.add_node(b"###test_node1###");
        let node2 = graph.add_node(b"###test_node2###");
        let node3 = graph.add_node(b"###test_node3###");
        let node4 = graph.add_node(b"###test_node4###");
        let node5 = graph.add_node(b"###test_node5###");
        graph.insert_link(node1, node2,b"###node1_eth1###",b"###node2_eth2###", 1);
        graph.insert_link(node2, node3,b"###node2_eth3###",b"###node3_eth4###", 1);
        graph.insert_link(node3, node4,b"###node3_eth5###",b"###node4_eth6###", 1);
        graph.insert_link(node4, node5,b"###node4_eth7###",b"###node5_eth8###", 1);
        graph.insert_link(node5, node1,b"###node5_eth9###",b"###node1_eth0###", 1);

        unsafe{
            (*node1).set_loopback_address(IP([127,0,0,1]));
            (*node1).set_intf_ip_address(b"###node1_eth1###", IP([192,168,0,1]), 24);
            (*node1).set_intf_ip_address(b"###node1_eth0###", IP([192,168,0,0]), 24);

            (*node2).set_loopback_address(IP([127,0,0,1]));
            (*node2).set_intf_ip_address(b"###node2_eth2###", IP([192,168,0,2]), 24);
            (*node2).set_intf_ip_address(b"###node2_eth3###", IP([192,168,0,3]), 24);

            (*node3).set_loopback_address(IP([127,0,0,1]));
            (*node3).set_intf_ip_address(b"###node3_eth4###", IP([192,168,0,4]), 24);
            (*node3).set_intf_ip_address(b"###node3_eth5###", IP([192,168,0,5]), 24);

            (*node4).set_loopback_address(IP([127,0,0,1]));
            (*node4).set_intf_ip_address(b"###node4_eth6###", IP([192,168,0,6]), 24);
            (*node4).set_intf_ip_address(b"###node4_eth7###", IP([192,168,0,7]), 24);

            (*node5).set_loopback_address(IP([127,0,0,1]));
            (*node5).set_intf_ip_address(b"###node5_eth8###", IP([192,168,0,8]), 24);
            (*node5).set_intf_ip_address(b"###node5_eth9###", IP([192,168,0,9]), 24);
            (*node1).init_udp_sock(3456);
            (*node2).init_udp_sock(40014);
            (*node5).init_udp_sock(40013);

            graph.start_pkt_receiver_thread();

            for i in 0..10 {
                let data = b"12";

                //(*node1).send_pkt_flood(data);
                sleep(Duration::from_millis(100));
            }
        }
        Ok(())
        //graph.dump_graph();
    }
}
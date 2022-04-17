use std::alloc::{alloc, Layout};
use memoffset::offset_of;
use crate::glthread::{*};
use crate::net::{*};

const TOPOLOGY_NAME: usize = 16;
const NODE_NAME_SIZE: usize = 16;
const IF_NAME_SIZE: usize = 16;
const MAX_INTF_PER_NODE: usize = 10;

#[repr(C)]
pub struct Graph {
    topology_name: [u8; TOPOLOGY_NAME],
    node_list: GLThread,
}

impl Graph {
    pub fn new(topology_name: &[u8; TOPOLOGY_NAME]) -> Self {
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
        unsafe{
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
        let boxed_link = Box::new(Link{
            if_src,
            if_des,
            cost,
        });
        let link = Box::into_raw(boxed_link);
        unsafe {
            (*if_src).link = link;
            (*if_des).link = link;

            if let Some(index) = (*node_src).get_node_intf_available_slot(){
                (*node_src).interfaces[index] = if_src;
            }
            if let Some(index) = (*node_des).get_node_intf_available_slot(){
                (*node_des).interfaces[index] = if_des;
            }
        }

    }

    #[inline]
    pub  fn get_node_by_node_name(&self, node_name: &[u8; NODE_NAME_SIZE]) -> *mut Node {
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

    pub fn dump_graph(&self) {
        let mut base = self.node_list.right;
        while !base.is_null() {
            unsafe{
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
    intf_props:InterfaceProperty,
}

impl Interface {
    pub fn set_mac_address(&mut self) {
        if self.att_node.is_null() {return;}
        let mut hash_code_val = 0;
        unsafe {
            hash_code_val = hash_code(&(*self.att_node).node_name, NODE_NAME_SIZE);
            hash_code_val *= hash_code(&self.if_name, IF_NAME_SIZE);
        }
        self.intf_props.set_interface_mac_address(hash_code_to_mac(hash_code_val));
    }

    pub fn set_ip_address(&mut self, ip: IP, mask: u8) {
        self.intf_props.set_interface_ip_address(ip, mask);
        self.intf_props.ipadd_config(true);
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
                            GLThread{ left: std::ptr::null_mut(), right: std::ptr::null_mut() });
            std::ptr::write(&mut node.node_proprs, NetWorkNodeProperty::init());
            p
        }
    }
    #[inline]
    pub fn get_node_intf_available_slot(&self) -> Option<usize> {
        self.interfaces.iter().position(|f| f.is_null())
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
        unsafe{
            for i in 0..MAX_INTF_PER_NODE {
                if self.interfaces[i].is_null() { break; }
                let intf = self.interfaces[i];
                println!("Interface Name = {}\n\tNbr Node {}, Local Node : {}, cost = {}",
                         std::str::from_utf8(&(*intf).if_name).unwrap(),
                         std::str::from_utf8(&(*get_nbr_node(intf)).node_name).unwrap(),
                         std::str::from_utf8(&(*(*intf).att_node).node_name).unwrap(),
                         (*(*intf).link).cost
                );
                (*intf).intf_props.dump();
            }
        }
    }

    #[inline]
    pub fn set_ip_address(&mut self, ip: IP) {
        self.node_proprs.set_loopback_address(ip);
        self.node_proprs.lb_addr_config(true);

    }

    pub fn set_intf_ip_address(&mut self,  if_name: &[u8; IF_NAME_SIZE], ip: IP, mask: u8) {
        let interface = self.get_node_if_by_name(if_name);

    }
}

#[inline]
pub unsafe fn get_nbr_node(interface: *mut Interface) -> *mut Node {
    if !(*interface).link.is_null() {
        match (*(*interface).link).if_src == interface {
            true => {return (*(*(*interface).link).if_des).att_node;},
            false => {return (*(*(*interface).link).if_src).att_node;},
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
    use crate::glthread::GLThread;
    use crate::graph::{Graph, graph_glue_to_node, Node};

    #[test]
    fn test_graph_glue_to_node() {
        let name = b"testtesttestestt";
        let node = Node::new(name);
        unsafe {
            let gp = &(*node).graph_glue as * const _ as *mut GLThread;
            let res = graph_glue_to_node(gp);
            assert_eq!(*name,(*res).node_name);
        }
    }

    #[test]
    fn test_graph() {
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
        graph.dump_graph();
    }
}
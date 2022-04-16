use std::alloc::{alloc, Layout};
use std::borrow::Borrow;
use std::collections::linked_list::LinkedList;
use memoffset::offset_of;
use crate::glthread::{*};

const NODE_NAME_SIZE: usize = 16;
const IF_NAME_SIZE: usize = 16;
const MAX_INTF_PER_NODE: usize = 10;

#[repr(C)]
pub struct Graph {
    topology_name: [u8; 30],
    node_list: GLThread,
}

impl Graph {
    pub fn new(topology_name: &[u8; 30]) -> *mut Self {
        let layout = Layout::new::<Graph>();
        unsafe {
            let p = alloc(layout) as *mut Self;
            let graph = &mut *p;
            std::ptr::write(&mut graph.topology_name, *topology_name);
            std::ptr::write(&mut graph.node_list,
                            GLThread{ left: std::ptr::null_mut(), right: std::ptr::null_mut() });
            p
        }
    }

    pub fn add_node(&mut self, node_name: &[u8; NODE_NAME_SIZE]) {
        let new_node = Node::new(node_name);
        unsafe{
            let curr_glthread = &self.node_list as *const _ as *mut GLThread;
            let new_glthread = &(*new_node).graph_glue as *const _ as *mut GLThread;
            glthread_add_next(curr_glthread, new_glthread);
        }
    }

    #[inline]
    pub unsafe fn get_node_by_node_name(&self, node_name: &[u8; NODE_NAME_SIZE]) -> *mut Node {
        let base = &self.node_list.right as *const _ as *mut GLThread;

        while !base.is_null() {
            let node = graph_glue_to_node(base);
            if (*node).node_name == *node_name {
                return node;
            }
        }
        std::ptr::null_mut()
    }
}


pub struct Interface {
    if_name: [u8; IF_NAME_SIZE],
    att_node: *mut Node,
    link: *mut Link,
}

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


pub unsafe fn graph_glue_to_node(glthread: *mut GLThread) -> *mut Node {
    let offset = offset_of!(Node, graph_glue);
    let node_addr = (glthread as usize) - offset;
    node_addr as *mut Node
}


#[cfg(test)]
mod test {
    use crate::glthread::GLThread;
    use crate::graph::{graph_glue_to_node, Node};

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
}
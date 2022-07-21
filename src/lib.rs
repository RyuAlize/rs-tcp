#![feature(linked_list_remove)]
#![feature(slice_take)]

extern crate core;

mod error;
pub mod topograph;
pub mod data_link_layer;
pub mod ip_layer;
mod packet;
mod config;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

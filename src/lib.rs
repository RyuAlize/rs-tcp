#![feature(in_band_lifetimes)]
#![feature(linked_list_remove)]

mod error;
mod topograph;
mod data_link_layer;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

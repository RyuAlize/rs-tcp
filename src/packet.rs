pub trait Packet {
    /// Return a slice to the packet header.
    fn header(&self) -> &[u8] {
        self.split().0
    }

    /// Return a slice to the packet payload.
    fn payload(&self) -> &[u8] {
        self.split().1
    }

    /// Return both slices.
    fn split(&self) -> (&[u8], &[u8]);
}


pub trait PacketMut {
    /// Returns a slice to the packet header.
    fn header_mut(&mut self) -> &mut [u8] {
        self.split_mut().0
    }

    /// Returns a slice to the packet payload.
    fn payload_mut(&mut self) -> &mut [u8] {
        self.split_mut().1
    }

    /// Return both mutable slices.
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]);
}
use std::str::Utf8Error;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error")]
    IOError(#[from] std::io::Error),

    #[error("socket not bind")]
    SocketNotBindError,

    #[error("invalid socket address")]
    SocketAddrParseError(#[from] std::net::AddrParseError),

    #[error("{}", 0)]
    ARPError(String),

    #[error("utf8 error")]
    Utf8Error(#[from] Utf8Error),

    #[error("dosen't find neighbor node")]
    NeighborNodeNotFound,

    #[error("interface not attach node")]
    InterfaceNotAttNode,
}

pub type Result<T> = std::result::Result<T, Error>;
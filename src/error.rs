use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error")]
    IOError(#[from] std::io::Error),

    #[error("socket not bind")]
    SocketNotBindError,

    #[error("invalid socket address")]
    SocketAddrParseErrpr(#[from] std::net::AddrParseError)
}

pub type Result<T> = std::result::Result<T, Error>;
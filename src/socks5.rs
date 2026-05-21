use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

pub const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;

#[derive(Debug, Clone)]
pub struct SocksAddr {
    pub data: Vec<u8>,
}

impl SocksAddr {
    pub fn to_string_addr(&self) -> String {
        if self.data.is_empty() {
            return String::new();
        }
        match self.data[0] {
            ATYP_IPV4 => {
                if self.data.len() < 7 { return String::new(); }
                let ip = Ipv4Addr::new(self.data[1], self.data[2], self.data[3], self.data[4]);
                let port = ((self.data[5] as u16) << 8) | self.data[6] as u16;
                format!("{}:{}", ip, port)
            }
            ATYP_DOMAIN => {
                if self.data.len() < 4 { return String::new(); }
                let host_len = self.data[1] as usize;
                if self.data.len() < 2 + host_len + 2 { return String::new(); }
                let host = String::from_utf8_lossy(&self.data[2..2 + host_len]);
                let port = ((self.data[2 + host_len] as u16) << 8) | self.data[3 + host_len] as u16;
                format!("{}:{}", host, port)
            }
            ATYP_IPV6 => {
                if self.data.len() < 19 { return String::new(); }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = ((self.data[17] as u16) << 8) | self.data[18] as u16;
                format!("[{}]:{}", ip, port)
            }
            _ => String::new(),
        }
    }

    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => {
                let mut data = vec![ATYP_IPV4];
                data.extend_from_slice(&v4.ip().octets());
                data.extend_from_slice(&v4.port().to_be_bytes());
                SocksAddr { data }
            }
            SocketAddr::V6(v6) => {
                let mut data = vec![ATYP_IPV6];
                data.extend_from_slice(&v6.ip().octets());
                data.extend_from_slice(&v6.port().to_be_bytes());
                SocksAddr { data }
            }
        }
    }
}

/// Perform SOCKS5 server handshake. Returns (target_addr, command).
pub async fn server_handshake(stream: &mut TcpStream) -> io::Result<(SocksAddr, u8)> {
    let mut buf = [0u8; MAX_ADDR_LEN + 3];

    // Read version and nmethods
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    if nmethods > 0 {
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
    }

    // Reply: version 5, no auth
    stream.write_all(&[5, 0]).await?;

    // Read request: VER CMD RSV ATYP DST.ADDR DST.PORT
    stream.read_exact(&mut buf[..3]).await?;
    let command = buf[1];

    let addr = read_addr(stream, &mut buf).await?;

    match command {
        CMD_CONNECT | CMD_UDP_ASSOCIATE => {
            let local_addr = stream.local_addr()?;
            let local_socks = SocksAddr::from_socket_addr(&local_addr);
            // VER REP RSV ATYP BND.ADDR BND.PORT
            stream.write_all(&[5, 0, 0]).await?;
            stream.write_all(&local_socks.data).await?;
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "command not supported"));
        }
    }

    Ok((addr, command))
}

async fn read_addr(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<SocksAddr> {
    stream.read_exact(&mut buf[..1]).await?;
    match buf[0] {
        ATYP_DOMAIN => {
            stream.read_exact(&mut buf[1..2]).await?;
            let domain_len = buf[1] as usize;
            stream.read_exact(&mut buf[2..2 + domain_len + 2]).await?;
            Ok(SocksAddr { data: buf[..1 + 1 + domain_len + 2].to_vec() })
        }
        ATYP_IPV4 => {
            stream.read_exact(&mut buf[1..1 + 4 + 2]).await?;
            Ok(SocksAddr { data: buf[..1 + 4 + 2].to_vec() })
        }
        ATYP_IPV6 => {
            stream.read_exact(&mut buf[1..1 + 16 + 2]).await?;
            Ok(SocksAddr { data: buf[..1 + 16 + 2].to_vec() })
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid address type")),
    }
}


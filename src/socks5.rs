use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

pub const REP_SUCCEEDED: u8 = 0;
pub const REP_GENERAL_FAILURE: u8 = 1;
pub const REP_HOST_UNREACHABLE: u8 = 4;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 7;

pub const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

#[derive(Debug, Clone)]
pub struct SocksAddr {
    pub data: Vec<u8>,
}

impl SocksAddr {
    pub fn to_string_addr(&self) -> Option<String> {
        if self.data.is_empty() {
            return None;
        }
        match self.data[0] {
            ATYP_IPV4 => {
                if self.data.len() < 7 {
                    return None;
                }
                let ip = Ipv4Addr::new(self.data[1], self.data[2], self.data[3], self.data[4]);
                let port = u16::from_be_bytes([self.data[5], self.data[6]]);
                Some(format!("{ip}:{port}"))
            }
            ATYP_DOMAIN => {
                if self.data.len() < 4 {
                    return None;
                }
                let host_len = self.data[1] as usize;
                if self.data.len() < 2 + host_len + 2 {
                    return None;
                }
                let host = String::from_utf8_lossy(&self.data[2..2 + host_len]);
                let port = u16::from_be_bytes([self.data[2 + host_len], self.data[3 + host_len]]);
                Some(format!("{host}:{port}"))
            }
            ATYP_IPV6 => {
                if self.data.len() < 19 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([self.data[17], self.data[18]]);
                Some(format!("[{ip}]:{port}"))
            }
            _ => None,
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

/// 完成 SOCKS5 方法协商并读取请求，返回（目标地址，命令）。
///
/// 成功应答由调用方在确认上游连接后再通过 [`send_reply`] 发送，这样 SOCKS 客户端
/// 收到 `REP_SUCCEEDED` 时才代表隧道真正可用。
pub async fn server_handshake(stream: &mut TcpStream) -> io::Result<(SocksAddr, u8)> {
    let mut buf = [0u8; MAX_ADDR_LEN + 3];

    // VER NMETHODS
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        stream.write_all(&[5, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no SOCKS5 auth methods offered",
        ));
    }

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[5, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client does not offer the no-auth method",
        ));
    }
    stream.write_all(&[5, METHOD_NO_AUTH]).await?;

    // VER CMD RSV
    stream.read_exact(&mut buf[..3]).await?;
    if buf[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not SOCKS5 request",
        ));
    }
    let command = buf[1];
    let addr = read_addr(stream, &mut buf).await?;

    Ok((addr, command))
}

/// 发送 SOCKS5 应答。BND.ADDR/BND.PORT 使用本地监听地址。
pub async fn send_reply(stream: &mut TcpStream, rep: u8) -> io::Result<()> {
    stream.write_all(&[5, rep, 0]).await?;
    let local = stream.local_addr()?;
    let bound = SocksAddr::from_socket_addr(&local);
    stream.write_all(&bound.data).await
}

async fn read_addr(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<SocksAddr> {
    stream.read_exact(&mut buf[..1]).await?;
    match buf[0] {
        ATYP_DOMAIN => {
            stream.read_exact(&mut buf[1..2]).await?;
            let domain_len = buf[1] as usize;
            stream.read_exact(&mut buf[2..2 + domain_len + 2]).await?;
            Ok(SocksAddr {
                data: buf[..1 + 1 + domain_len + 2].to_vec(),
            })
        }
        ATYP_IPV4 => {
            stream.read_exact(&mut buf[1..1 + 4 + 2]).await?;
            Ok(SocksAddr {
                data: buf[..1 + 4 + 2].to_vec(),
            })
        }
        ATYP_IPV6 => {
            stream.read_exact(&mut buf[1..1 + 16 + 2]).await?;
            Ok(SocksAddr {
                data: buf[..1 + 16 + 2].to_vec(),
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid address type",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let socks = SocksAddr::from_socket_addr(&addr);
        assert_eq!(socks.to_string_addr().as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn ipv6_roundtrip() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let socks = SocksAddr::from_socket_addr(&addr);
        assert_eq!(socks.to_string_addr().as_deref(), Some("[::1]:443"));
    }

    #[test]
    fn domain_address_format() {
        let mut data = vec![ATYP_DOMAIN, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let socks = SocksAddr { data };
        assert_eq!(socks.to_string_addr().as_deref(), Some("example.com:443"));
    }

    #[test]
    fn malformed_address_returns_none() {
        assert_eq!(SocksAddr { data: vec![] }.to_string_addr(), None);
        assert_eq!(
            SocksAddr {
                data: vec![ATYP_IPV4, 1, 2]
            }
            .to_string_addr(),
            None
        );
        assert_eq!(SocksAddr { data: vec![0x09] }.to_string_addr(), None);
    }
}

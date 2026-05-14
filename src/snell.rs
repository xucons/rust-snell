use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::aead::{self, AeadCipher, Cipher, PAYLOAD_SIZE_MASK, SALT_SIZE};
use crate::obfs::{ObfsMode, ObfsState};
use crate::socks5;

// Snell protocol constants
pub const CMD_PING: u8 = 0;
pub const CMD_CONNECT: u8 = 1;
pub const CMD_CONNECT_V2: u8 = 5;
pub const CMD_UDP: u8 = 6;
pub const CMD_UDP_FORWARD: u8 = 1;

pub const RESP_TUNNEL: u8 = 0;
pub const RESP_READY: u8 = 0;
pub const RESP_PONG: u8 = 1;
pub const RESP_ERROR: u8 = 2;

pub const SNELL_VERSION: u8 = 1;

const RELAY_BUF_SIZE: usize = 20 * 1024;

#[derive(Debug)]
pub struct ZeroChunkError;

impl std::fmt::Display for ZeroChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Snell ZERO_CHUNK occurred")
    }
}
impl std::error::Error for ZeroChunkError {}

/// A Snell connection with AEAD encryption and optional obfuscation.
pub struct SnellConn {
    stream: TcpStream,
    obfs: ObfsState,
    cipher: Box<dyn Cipher>,
    fallback_cipher: Option<Box<dyn Cipher>>,
    read_aead: Option<Box<dyn AeadCipher>>,
    write_aead: Option<Box<dyn AeadCipher>>,
    fallback_aead: Option<Box<dyn AeadCipher>>,
    read_nonce: Vec<u8>,
    write_nonce: Vec<u8>,
    // Buffer for de-obfuscated but still AEAD-encrypted data
    enc_buf: Vec<u8>,
    enc_pos: usize,
    // Buffer for AEAD-decrypted but not yet consumed data
    dec_leftover: Vec<u8>,
    switched: bool,
}

impl SnellConn {
    pub fn new_server_conn(stream: TcpStream, psk: &[u8], obfs_type: &str) -> io::Result<Self> {
        let cipher = aead::new_aes128_gcm(psk);
        let fallback_cipher = Some(aead::new_chacha20_poly1305(psk));
        let obfs_mode = match obfs_type {
            "tls" => ObfsMode::TlsServer,
            "http" => ObfsMode::HttpServer,
            _ => ObfsMode::None,
        };
        Ok(Self {
            stream,
            obfs: ObfsState::new(obfs_mode),
            cipher,
            fallback_cipher,
            read_aead: None,
            write_aead: None,
            fallback_aead: None,
            read_nonce: Vec::new(),
            write_nonce: Vec::new(),
            enc_buf: Vec::new(),
            enc_pos: 0,
            dec_leftover: Vec::new(),
            switched: false,
        })
    }

    pub fn new_client_conn(
        stream: TcpStream,
        psk: &[u8],
        obfs_type: &str,
        obfs_host: &str,
        server_port: &str,
        is_v2: bool,
    ) -> io::Result<Self> {
        let cipher = if is_v2 {
            aead::new_aes128_gcm(psk)
        } else {
            aead::new_chacha20_poly1305(psk)
        };
        let obfs_mode = match obfs_type {
            "tls" => ObfsMode::TlsClient { host: obfs_host.to_string() },
            "http" => ObfsMode::HttpClient { host: obfs_host.to_string(), port: server_port.to_string() },
            _ => ObfsMode::None,
        };
        Ok(Self {
            stream,
            obfs: ObfsState::new(obfs_mode),
            cipher,
            fallback_cipher: None,
            read_aead: None,
            write_aead: None,
            fallback_aead: None,
            read_nonce: Vec::new(),
            write_nonce: Vec::new(),
            enc_buf: Vec::new(),
            enc_pos: 0,
            dec_leftover: Vec::new(),
            switched: false,
        })
    }

    /// Read exactly N bytes from the obfs layer into enc_buf, then copy to `buf`.
    async fn obfs_read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            // Drain enc_buf first
            if self.enc_pos < self.enc_buf.len() {
                let n = std::cmp::min(buf.len() - filled, self.enc_buf.len() - self.enc_pos);
                buf[filled..filled + n].copy_from_slice(&self.enc_buf[self.enc_pos..self.enc_pos + n]);
                self.enc_pos += n;
                filled += n;
                continue;
            }
            // Reset buffer
            self.enc_buf.clear();
            self.enc_pos = 0;

            // Read from obfs layer
            let mut tmp = vec![0u8; 4096];
            let n = self.obfs.read(&mut self.stream, &mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
            }
            self.enc_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    /// Initialize the AEAD reader by reading the salt from the peer.
    async fn init_reader(&mut self) -> io::Result<()> {
        let mut salt = vec![0u8; SALT_SIZE];
        self.obfs_read_exact(&mut salt).await?;

        let primary = self.cipher.decrypter(&salt);
        self.read_nonce = vec![0u8; primary.nonce_size()];
        self.read_aead = Some(primary);

        // Prepare fallback AEAD for the first record
        if let Some(ref fb_cipher) = self.fallback_cipher {
            self.fallback_aead = Some(fb_cipher.decrypter(&salt));
        }
        Ok(())
    }

    /// Initialize the AEAD writer by generating and sending a salt.
    async fn init_writer(&mut self) -> io::Result<()> {
        let mut salt = vec![0u8; SALT_SIZE];
        {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut salt[..]);
        }
        let enc = self.cipher.encrypter(&salt);
        self.obfs.write(&mut self.stream, &salt).await?;
        self.write_aead = Some(enc);
        self.write_nonce = vec![0u8; self.write_aead.as_ref().unwrap().nonce_size()];
        Ok(())
    }

    /// Read and decrypt a single AEAD record.
    async fn read_record(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let overhead = self.read_aead.as_ref().unwrap().tag_size();

        // Read encrypted header (2 bytes + tag)
        let header_enc_size = 2 + overhead;
        let mut enc_header = vec![0u8; header_enc_size];
        self.obfs_read_exact(&mut enc_header).await?;

        // Try decrypt with primary, fall back if needed
        let header = if self.fallback_aead.is_some() {
            let primary = self.read_aead.as_ref().unwrap();
            match primary.decrypt(&self.read_nonce, &enc_header) {
                Ok(h) => h,
                Err(_) => {
                    let fb = self.fallback_aead.take().unwrap();
                    let h = fb.decrypt(&self.read_nonce, &enc_header)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    self.read_aead = Some(fb);
                    self.switched = true;
                    h
                }
            }
        } else {
            self.read_aead.as_ref().unwrap().decrypt(&self.read_nonce, &enc_header)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        };
        aead::increment_nonce(&mut self.read_nonce);

        let size = ((header[0] as usize) << 8 | header[1] as usize) & PAYLOAD_SIZE_MASK;
        if size == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, ZeroChunkError));
        }

        // Read encrypted payload
        let payload_enc_size = size + overhead;
        let mut enc_payload = vec![0u8; payload_enc_size];
        self.obfs_read_exact(&mut enc_payload).await?;

        let payload = self.read_aead.as_ref().unwrap().decrypt(&self.read_nonce, &enc_payload)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        aead::increment_nonce(&mut self.read_nonce);

        let n = std::cmp::min(buf.len(), payload.len());
        buf[..n].copy_from_slice(&payload[..n]);
        if n < payload.len() {
            self.dec_leftover = payload[n..].to_vec();
        }

        Ok(n)
    }

    /// Read plaintext from the AEAD stream.
    pub async fn snell_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Return decrypted leftover first
        if !self.dec_leftover.is_empty() {
            let n = std::cmp::min(buf.len(), self.dec_leftover.len());
            buf[..n].copy_from_slice(&self.dec_leftover[..n]);
            self.dec_leftover.drain(..n);
            return Ok(n);
        }

        // Init reader if needed
        if self.read_aead.is_none() {
            self.init_reader().await?;
        }

        self.read_record(buf).await
    }

    /// Write plaintext to the AEAD stream.
    pub async fn snell_write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.write_aead.is_none() {
            self.init_writer().await?;
        }

        if data.is_empty() {
            // Zero chunk
            let aead = self.write_aead.as_ref().unwrap();
            let encrypted = aead.encrypt(&self.write_nonce, &[0, 0])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            aead::increment_nonce(&mut self.write_nonce);
            self.obfs.write(&mut self.stream, &encrypted).await?;
            return Ok(0);
        }

        let data_len = data.len();
        let mut written = 0;
        while written < data_len {
            let end = std::cmp::min(written + PAYLOAD_SIZE_MASK, data_len);
            let chunk = &data[written..end];
            self.write_chunk(chunk).await?;
            written = end;
        }
        Ok(data_len)
    }

    async fn write_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let aead = self.write_aead.as_ref().unwrap();
        let payload_len = payload.len();

        // Encrypt header
        let header = [(payload_len >> 8) as u8, (payload_len & 0xff) as u8];
        let enc_header = aead.encrypt(&self.write_nonce, &header)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        aead::increment_nonce(&mut self.write_nonce);

        // Encrypt payload
        let enc_payload = aead.encrypt(&self.write_nonce, payload)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        aead::increment_nonce(&mut self.write_nonce);

        // Write through obfs
        let mut out = Vec::with_capacity(enc_header.len() + enc_payload.len());
        out.extend_from_slice(&enc_header);
        out.extend_from_slice(&enc_payload);
        self.obfs.write(&mut self.stream, &out).await?;
        Ok(())
    }

    /// Write a zero chunk (for v2 multiplexing signal).
    pub async fn write_zero_chunk(&mut self) -> io::Result<()> {
        self.snell_write(&[]).await?;
        Ok(())
    }

    /// Read the server's response byte.
    pub async fn read_response(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.snell_read(&mut buf).await?;
        Ok(buf[0])
    }

    /// Read the error response details after getting RESP_ERROR.
    pub async fn read_error_response(&mut self) -> io::Result<String> {
        let mut code_buf = [0u8; 1];
        self.snell_read(&mut code_buf).await?;
        let mut len_buf = [0u8; 1];
        self.snell_read(&mut len_buf).await?;
        let len = len_buf[0] as usize;
        let mut msg = vec![0u8; len];
        if len > 0 {
            self.snell_read(&mut msg).await?;
        }
        Ok(String::from_utf8_lossy(&msg).to_string())
    }
}

// ---- Server ----

pub async fn run_server(listen: &str, psk: &str, obfs_type: &str) -> io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("snell server listening at: {}", listen);

    let psk = psk.to_string();
    let obfs_type = obfs_type.to_string();

    loop {
        let (stream, addr) = listener.accept().await?;
        let psk = psk.clone();
        let obfs_type = obfs_type.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(stream, &psk, &obfs_type).await {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    log::warn!("connection from {} error: {}", addr, e);
                }
            }
        });
    }
}

async fn handle_server_conn(stream: TcpStream, psk: &str, obfs_type: &str) -> io::Result<()> {
    let mut conn = SnellConn::new_server_conn(stream, psk.as_bytes(), obfs_type)?;

    let mut is_v2 = true;

    loop {
        let (target, command) = match server_handshake(&mut conn).await {
            Ok(r) => r,
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    log::warn!("handshake failed: {}", e);
                }
                break;
            }
        };

        if command != CMD_UDP {
            log::info!("new target: {}", target);
        }

        if command == CMD_PING {
            conn.snell_write(&[RESP_PONG]).await?;
            break;
        }

        match command {
            CMD_CONNECT => is_v2 = false,
            CMD_UDP => {
                handle_udp_request(&mut conn).await?;
                break;
            }
            CMD_CONNECT_V2 => {}
            _ => {
                log::error!("unknown command 0x{:x}", command);
                break;
            }
        }

        // Connect to target
        let tc = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                write_error(&mut conn, &e.to_string()).await?;
                if !is_v2 { break; }
                continue;
            }
        };

        conn.snell_write(&[RESP_TUNNEL]).await?;

        // Relay
        let relay_result = relay_conn_to_tcp(&mut conn, tc).await;

        if is_v2 {
            // Write zero chunk back
            if let Err(e) = conn.write_zero_chunk().await {
                log::error!("zero chunk write error: {}", e);
                return Ok(());
            }

            // Drain until zero chunk from client
            let mut buf = vec![0u8; RELAY_BUF_SIZE];
            loop {
                match conn.snell_read(&mut buf).await {
                    Ok(_) => continue,
                    Err(e) => {
                        if is_zero_chunk(&e) {
                            break;
                        }
                        if e.kind() != io::ErrorKind::UnexpectedEof {
                            log::warn!("unexpected error draining: {}", e);
                        }
                        break;
                    }
                }
            }
        } else {
            break;
        }

        let _ = relay_result;
    }

    Ok(())
}

async fn server_handshake(conn: &mut SnellConn) -> io::Result<(String, u8)> {
    let mut buf = [0u8; 3];
    conn.snell_read(&mut buf).await?;

    if buf[0] != SNELL_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid snell version {:x}", buf[0])));
    }

    let command = buf[1];
    let client_id_len = buf[2] as usize;

    if client_id_len > 0 {
        let mut client_id = vec![0u8; client_id_len];
        conn.snell_read(&mut client_id).await?;
        log::debug!("client id: {}", String::from_utf8_lossy(&client_id));
    }

    if command == CMD_UDP {
        return Ok((String::new(), CMD_UDP));
    }

    // Read host
    let mut hlen_buf = [0u8; 1];
    conn.snell_read(&mut hlen_buf).await?;
    let hlen = hlen_buf[0] as usize;

    let mut host_port = vec![0u8; hlen + 2];
    conn.snell_read(&mut host_port).await?;

    let host = String::from_utf8_lossy(&host_port[..hlen]).to_string();
    let port = ((host_port[hlen] as u16) << 8) | host_port[hlen + 1] as u16;

    Ok((format!("{}:{}", host, port), command))
}

async fn write_error(conn: &mut SnellConn, msg: &str) -> io::Result<()> {
    let mut buf = vec![RESP_ERROR, 0]; // code=0
    let msg_bytes = msg.as_bytes();
    let truncated = if msg_bytes.len() > 250 { &msg_bytes[..250] } else { msg_bytes };
    buf.push(truncated.len() as u8);
    buf.extend_from_slice(truncated);
    conn.snell_write(&buf).await?;
    Ok(())
}

async fn handle_udp_request(conn: &mut SnellConn) -> io::Result<()> {
    log::info!("new UDP request");

    let udp_sock = UdpSocket::bind("0.0.0.0:0").await?;
    conn.snell_write(&[RESP_READY]).await?;

    let local_addr = udp_sock.local_addr()?;
    log::info!("UDP listening on: {}", local_addr);

    let mut cache = lru::LruCache::new(std::num::NonZeroUsize::new(256).unwrap());
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        let n = match conn.snell_read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    log::info!("UDP over TCP read EOF");
                } else {
                    log::error!("UDP over TCP read error: {}", e);
                }
                break;
            }
        };

        if n < 5 {
            log::error!("UDP insufficient chunk size: {} < 5", n);
            break;
        }

        let cmd = buf[0];
        let hlen = buf[1];

        if cmd != CMD_UDP_FORWARD {
            log::error!("UDP unknown command: 0x{:x}", cmd);
            break;
        }

        let (host, head) = if hlen == 0 {
            let ip_ver = buf[2];
            let iplen = match ip_ver {
                4 => 4usize,
                6 => 16usize,
                _ => {
                    log::error!("unknown IP version: {}", ip_ver);
                    break;
                }
            };
            let head = 3 + iplen;
            if n < head + 2 {
                log::error!("UDP insufficient chunk size");
                break;
            }
            let ip_bytes = &buf[3..head];
            let ip = if iplen == 4 {
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
            } else {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip_bytes);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            };
            (ip.to_string(), head)
        } else {
            let head = 2 + hlen as usize;
            if n < head + 2 {
                log::error!("UDP insufficient chunk size");
                break;
            }
            (String::from_utf8_lossy(&buf[2..head]).to_string(), head)
        };

        let port = ((buf[head] as u16) << 8) | buf[head + 1] as u16;
        let target = format!("{}:{}", host, port);
        log::debug!("UDP over TCP forwarding to {}", target);

        let uaddr = if let Some(&addr) = cache.get(&target) {
            addr
        } else {
            match tokio::net::lookup_host(&target).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        cache.put(target.clone(), addr);
                        addr
                    } else {
                        log::warn!("UDP failed to resolve {}", target);
                        continue;
                    }
                }
                Err(e) => {
                    log::warn!("UDP failed to resolve {}: {}", target, e);
                    continue;
                }
            }
        };

        let payload_start = head + 2;
        if n > payload_start {
            if let Err(e) = udp_sock.send_to(&buf[payload_start..n], uaddr).await {
                log::error!("UDP send error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

// ---- Client ----

#[derive(Clone)]
pub struct SnellClient {
    server: String,
    obfs: String,
    obfs_host: String,
    psk: String,
    is_v2: bool,
}

impl SnellClient {
    pub fn new(server: &str, obfs: &str, obfs_host: &str, psk: &str, is_v2: bool) -> Self {
        Self {
            server: server.to_string(),
            obfs: obfs.to_string(),
            obfs_host: obfs_host.to_string(),
            psk: psk.to_string(),
            is_v2,
        }
    }

    pub async fn run(&self, listen: &str) -> io::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        log::info!("SOCKS proxy listening at: {}", listen);

        loop {
            let (stream, _) = listener.accept().await?;
            let client = self.clone();
            tokio::spawn(async move {
                if let Err(e) = client.handle_socks_conn(stream).await {
                    log::warn!("socks connection error: {}", e);
                }
            });
        }
    }

    async fn handle_socks_conn(&self, mut socks_stream: TcpStream) -> io::Result<()> {
        let (addr, command) = socks5::server_handshake(&mut socks_stream).await?;

        if command == socks5::CMD_UDP_ASSOCIATE {
            let mut buf = vec![0u8; 1024];
            loop {
                match socks_stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    _ => {}
                }
            }
            return Ok(());
        }

        let target = addr.to_string_addr();
        log::info!("new target: {}", target);

        let mut snell_conn = self.create_session(&target).await?;

        // Read server response
        let resp = snell_conn.read_response().await?;
        if resp == RESP_ERROR {
            let msg = snell_conn.read_error_response().await?;
            return Err(io::Error::new(io::ErrorKind::Other, format!("server error: {}", msg)));
        } else if resp != RESP_TUNNEL {
            return Err(io::Error::new(io::ErrorKind::Other, "command not supported"));
        }

        // Relay
        let _ = relay_tcp_to_conn(&mut socks_stream, &mut snell_conn).await;

        if self.is_v2 {
            if let Err(e) = snell_conn.write_zero_chunk().await {
                log::error!("zero chunk write error: {}", e);
                return Ok(());
            }

            // Drain until zero chunk
            let mut buf = vec![0u8; RELAY_BUF_SIZE];
            loop {
                match snell_conn.snell_read(&mut buf).await {
                    Ok(_) => continue,
                    Err(e) => {
                        if is_zero_chunk(&e) {
                            break;
                        }
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn create_session(&self, target: &str) -> io::Result<SnellConn> {
        let stream = TcpStream::connect(&self.server).await?;
        let (_, server_port) = self.server.rsplit_once(':').unwrap_or(("", &self.server));

        let mut conn = SnellConn::new_client_conn(
            stream, self.psk.as_bytes(), &self.obfs, &self.obfs_host, server_port, self.is_v2,
        )?;

        write_header(&mut conn, target, self.is_v2).await?;
        Ok(conn)
    }
}

async fn write_header(conn: &mut SnellConn, target: &str, is_v2: bool) -> io::Result<()> {
    let (host, port_str) = target.rsplit_once(':').unwrap_or((target, "0"));
    let port: u16 = port_str.parse().unwrap_or(0);

    let mut buf = Vec::with_capacity(1 + 1 + 1 + 1 + host.len() + 2);
    buf.push(SNELL_VERSION);
    buf.push(if is_v2 { CMD_CONNECT_V2 } else { CMD_CONNECT });
    buf.push(0); // client ID length = 0
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());

    conn.snell_write(&buf).await?;
    Ok(())
}

// ---- Relay ----

/// Relay between a SnellConn and a TcpStream (server mode: snell is left, target is right).
async fn relay_conn_to_tcp(snell: &mut SnellConn, target: TcpStream) -> io::Result<()> {
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let mut snell_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut target_buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            r = snell.snell_read(&mut snell_buf) => {
                match r {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = target_write.write_all(&snell_buf[..n]).await {
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
            r = target_read.read(&mut target_buf) => {
                match r {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = snell.snell_write(&target_buf[..n]).await {
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        }
    }
}

/// Relay between a TcpStream (SOCKS client) and a SnellConn (server connection).
async fn relay_tcp_to_conn(socks: &mut TcpStream, snell: &mut SnellConn) -> io::Result<()> {
    let mut socks_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut snell_buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            r = socks.read(&mut socks_buf) => {
                match r {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = snell.snell_write(&socks_buf[..n]).await {
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
            r = snell.snell_read(&mut snell_buf) => {
                match r {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = socks.write_all(&snell_buf[..n]).await {
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        }
    }
}

fn is_zero_chunk(e: &io::Error) -> bool {
    e.get_ref().map_or(false, |inner| inner.is::<ZeroChunkError>())
}

use std::cmp::min;
use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::aead::{self, AeadCipher, Cipher, CipherKind, PAYLOAD_SIZE_MASK, SALT_SIZE};
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
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 8192;
const STAGING_COMPACT_THRESHOLD: usize = 64 * 1024;

/// Snell 连接上的错误。零长度分片是正常的流结束信号，因此和 I/O 错误分开表示。
#[derive(Debug)]
pub enum SnellError {
    Io(io::Error),
    ZeroChunk,
}

impl std::fmt::Display for SnellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::ZeroChunk => f.write_str("snell zero chunk"),
        }
    }
}

impl std::error::Error for SnellError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ZeroChunk => None,
        }
    }
}

impl From<io::Error> for SnellError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl SnellError {
    /// 对端正常关闭时的错误：零分片、EOF 或连接重置。
    fn is_eof(&self) -> bool {
        match self {
            Self::ZeroChunk => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ),
        }
    }

    fn is_quiet(&self) -> bool {
        self.is_eof()
    }
}

#[derive(Debug, Clone, Copy)]
enum ReadState {
    Header,
    Payload { size: usize },
}

/// A Snell connection with AEAD encryption and optional obfuscation.
pub struct SnellConn {
    stream: TcpStream,
    obfs: ObfsState,
    cipher: Cipher,
    fallback_cipher: Option<Cipher>,
    read_aead: Option<AeadCipher>,
    write_aead: Option<AeadCipher>,
    fallback_aead: Option<AeadCipher>,
    read_nonce: Vec<u8>,
    write_nonce: Vec<u8>,
    // 已从 obfs 层读出、尚未解析成完整 AEAD 帧的密文
    staging: Vec<u8>,
    staging_pos: usize,
    // 已解密、尚未被调用方消费的明文
    dec_leftover: Vec<u8>,
    read_state: ReadState,
}

impl SnellConn {
    pub fn new_server_conn(stream: TcpStream, psk: &[u8], obfs_type: &str) -> Self {
        let obfs = match obfs_type {
            "tls" => ObfsState::new(ObfsMode::TlsServer),
            "http" => ObfsState::new(ObfsMode::HttpServer),
            _ => ObfsState::new(ObfsMode::None),
        };
        Self {
            stream,
            obfs,
            cipher: Cipher::new(CipherKind::Aes128Gcm, psk),
            fallback_cipher: Some(Cipher::new(CipherKind::ChaCha20Poly1305, psk)),
            read_aead: None,
            write_aead: None,
            fallback_aead: None,
            read_nonce: Vec::new(),
            write_nonce: Vec::new(),
            staging: Vec::new(),
            staging_pos: 0,
            dec_leftover: Vec::new(),
            read_state: ReadState::Header,
        }
    }

    pub fn new_client_conn(
        stream: TcpStream,
        psk: &[u8],
        obfs_type: &str,
        obfs_host: &str,
        server_port: &str,
        is_v2: bool,
    ) -> Self {
        let obfs = match obfs_type {
            "tls" => ObfsState::new(ObfsMode::TlsClient).with_server(obfs_host, server_port),
            "http" => ObfsState::new(ObfsMode::HttpClient).with_server(obfs_host, server_port),
            _ => ObfsState::new(ObfsMode::None),
        };
        let kind = if is_v2 {
            CipherKind::Aes128Gcm
        } else {
            CipherKind::ChaCha20Poly1305
        };
        Self {
            stream,
            obfs,
            cipher: Cipher::new(kind, psk),
            fallback_cipher: None,
            read_aead: None,
            write_aead: None,
            fallback_aead: None,
            read_nonce: Vec::new(),
            write_nonce: Vec::new(),
            staging: Vec::new(),
            staging_pos: 0,
            dec_leftover: Vec::new(),
            read_state: ReadState::Header,
        }
    }

    fn staged_len(&self) -> usize {
        self.staging.len() - self.staging_pos
    }

    fn take_staged(&mut self, n: usize) -> Vec<u8> {
        debug_assert!(self.staged_len() >= n);
        let start = self.staging_pos;
        self.staging_pos += n;
        let out = self.staging[start..start + n].to_vec();
        if self.staging_pos == self.staging.len() {
            self.staging.clear();
            self.staging_pos = 0;
        } else if self.staging_pos >= STAGING_COMPACT_THRESHOLD {
            self.staging.drain(..self.staging_pos);
            self.staging_pos = 0;
        }
        out
    }

    /// 确保暂存区至少持有 `needed` 个字节。
    ///
    /// 该函数可安全取消：从 socket 读到的字节会立即保存到 `self.staging`，且
    /// `staging_pos` 只有在整帧解析完成后才会推进。
    async fn ensure_staged(&mut self, needed: usize) -> io::Result<()> {
        while self.staged_len() < needed {
            let mut chunk = [0u8; READ_CHUNK];
            let read = self.obfs.read(&mut self.stream, &mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            self.staging.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    /// 读取 salt 并初始化读方向的 AEAD 状态。
    async fn init_reader(&mut self) -> io::Result<()> {
        self.ensure_staged(SALT_SIZE).await?;
        let salt = self.take_staged(SALT_SIZE);

        let primary = self.cipher.aead(&salt);
        self.read_nonce = vec![0u8; AeadCipher::NONCE_SIZE];
        self.read_aead = Some(primary);

        if let Some(fallback) = &self.fallback_cipher {
            self.fallback_aead = Some(fallback.aead(&salt));
        }
        Ok(())
    }

    /// 生成 salt 并发送，初始化写方向的 AEAD 状态。
    async fn init_writer(&mut self) -> io::Result<()> {
        use rand::RngCore;

        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let aead = self.cipher.aead(&salt);
        self.obfs.write(&mut self.stream, &salt).await?;
        self.write_nonce = vec![0u8; AeadCipher::NONCE_SIZE];
        self.write_aead = Some(aead);
        Ok(())
    }

    async fn read_header(&mut self) -> Result<Vec<u8>, SnellError> {
        self.ensure_staged(2 + AeadCipher::TAG_SIZE).await?;
        let encrypted = self.take_staged(2 + AeadCipher::TAG_SIZE);
        self.decrypt_header(&encrypted)
    }

    /// 解密头部，必要时在首条记录上回退到 ChaCha20-Poly1305。
    fn decrypt_header(&mut self, encrypted: &[u8]) -> Result<Vec<u8>, SnellError> {
        let primary_result = self
            .read_aead
            .as_ref()
            .expect("read cipher initialized")
            .decrypt(&self.read_nonce, encrypted);

        match primary_result {
            Ok(header) => {
                aead::increment_nonce(&mut self.read_nonce);
                // 首条记录已确认密码套件，回退不再需要
                self.fallback_aead = None;
                self.fallback_cipher = None;
                Ok(header)
            }
            Err(primary_error) => {
                let Some(fallback) = self.fallback_aead.take() else {
                    return Err(io::Error::other(primary_error).into());
                };
                match fallback.decrypt(&self.read_nonce, encrypted) {
                    Ok(header) => {
                        if self.write_aead.is_some() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "cipher fallback after the write cipher was initialized",
                            )
                            .into());
                        }
                        log::info!("cipher fallback to chacha20-poly1305");
                        self.read_aead = Some(fallback);
                        self.cipher = self
                            .fallback_cipher
                            .take()
                            .expect("fallback cipher accompanies fallback AEAD");
                        aead::increment_nonce(&mut self.read_nonce);
                        Ok(header)
                    }
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AEAD decrypt failed with both aes-128-gcm and chacha20-poly1305, likely PSK mismatch",
                    )
                    .into()),
                }
            }
        }
    }

    async fn read_payload(&mut self, size: usize) -> Result<Vec<u8>, SnellError> {
        self.ensure_staged(size + AeadCipher::TAG_SIZE).await?;
        let encrypted = self.take_staged(size + AeadCipher::TAG_SIZE);
        let payload = self
            .read_aead
            .as_ref()
            .expect("read cipher initialized")
            .decrypt(&self.read_nonce, &encrypted)
            .map_err(io::Error::other)?;
        aead::increment_nonce(&mut self.read_nonce);
        Ok(payload)
    }

    /// 读取明文。
    ///
    /// 该函数可安全地被 `tokio::select!` 取消：所有中间状态（暂存密文、当前读取阶段、
    /// nonce）都保存在 `self` 中，只有完整读取并解密一帧后才会推进状态。
    pub async fn snell_read(&mut self, buf: &mut [u8]) -> Result<usize, SnellError> {
        if !self.dec_leftover.is_empty() {
            let n = min(buf.len(), self.dec_leftover.len());
            buf[..n].copy_from_slice(&self.dec_leftover[..n]);
            self.dec_leftover.drain(..n);
            return Ok(n);
        }

        if self.read_aead.is_none() {
            self.init_reader().await?;
        }

        loop {
            match self.read_state {
                ReadState::Header => {
                    let header = self.read_header().await?;
                    let size = ((usize::from(header[0]) << 8) | usize::from(header[1]))
                        & PAYLOAD_SIZE_MASK;
                    if size == 0 {
                        return Err(SnellError::ZeroChunk);
                    }
                    self.read_state = ReadState::Payload { size };
                }
                ReadState::Payload { size } => {
                    let payload = self.read_payload(size).await?;
                    self.read_state = ReadState::Header;
                    let n = min(buf.len(), payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    if n < payload.len() {
                        self.dec_leftover = payload[n..].to_vec();
                    }
                    return Ok(n);
                }
            }
        }
    }

    /// 写入明文。
    pub async fn snell_write(&mut self, data: &[u8]) -> Result<usize, SnellError> {
        if self.write_aead.is_none() {
            self.init_writer().await?;
        }

        if data.is_empty() {
            let encrypted = {
                let aead = self.write_aead.as_ref().expect("write cipher initialized");
                let encrypted = aead
                    .encrypt(&self.write_nonce, &[0, 0])
                    .map_err(io::Error::other)?;
                aead::increment_nonce(&mut self.write_nonce);
                encrypted
            };
            self.obfs.write(&mut self.stream, &encrypted).await?;
            return Ok(0);
        }

        let data_len = data.len();
        let mut written = 0;
        while written < data_len {
            let end = min(written + PAYLOAD_SIZE_MASK, data_len);
            self.write_chunk(&data[written..end]).await?;
            written = end;
        }
        Ok(data_len)
    }

    async fn write_chunk(&mut self, payload: &[u8]) -> Result<(), SnellError> {
        let payload_len = payload.len();
        let header = u16::try_from(payload_len)
            .expect("payload length <= PAYLOAD_SIZE_MASK")
            .to_be_bytes();

        let encrypted_header = {
            let aead = self.write_aead.as_ref().expect("write cipher initialized");
            let encrypted = aead
                .encrypt(&self.write_nonce, &header)
                .map_err(io::Error::other)?;
            aead::increment_nonce(&mut self.write_nonce);
            encrypted
        };

        let encrypted_payload = {
            let aead = self.write_aead.as_ref().expect("write cipher initialized");
            let encrypted = aead
                .encrypt(&self.write_nonce, payload)
                .map_err(io::Error::other)?;
            aead::increment_nonce(&mut self.write_nonce);
            encrypted
        };

        let mut out = Vec::with_capacity(encrypted_header.len() + encrypted_payload.len());
        out.extend_from_slice(&encrypted_header);
        out.extend_from_slice(&encrypted_payload);
        self.obfs.write(&mut self.stream, &out).await?;
        Ok(())
    }

    /// 写入零长度分片（v2 的半关闭信号）。
    pub async fn write_zero_chunk(&mut self) -> Result<(), SnellError> {
        self.snell_write(&[]).await?;
        Ok(())
    }

    /// 读取服务端应答字节。
    pub async fn read_response(&mut self) -> Result<u8, SnellError> {
        let mut buf = [0u8; 1];
        self.snell_read(&mut buf).await?;
        Ok(buf[0])
    }

    /// 在收到 `RESP_ERROR` 后读取错误详情。
    pub async fn read_error_response(&mut self) -> Result<String, SnellError> {
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
    log::info!(
        "snell server listening at: {listen}, obfs: {}",
        if obfs_type.is_empty() {
            "none"
        } else {
            obfs_type
        }
    );

    let psk = psk.to_string();
    let obfs_type = obfs_type.to_string();

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                // 瞬时错误（如 EMFILE）不应终止整个服务
                log::warn!("accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let psk = psk.clone();
        let obfs_type = obfs_type.clone();
        log::info!("connection from {addr}");
        tokio::spawn(async move {
            if let Err(error) = handle_server_conn(stream, &psk, &obfs_type).await {
                if !error.is_quiet() {
                    log::warn!("connection from {addr} error: {error}");
                }
            }
            log::info!("connection from {addr} closed");
        });
    }
}

async fn handle_server_conn(
    stream: TcpStream,
    psk: &str,
    obfs_type: &str,
) -> Result<(), SnellError> {
    let mut conn = SnellConn::new_server_conn(stream, psk.as_bytes(), obfs_type);
    let mut is_v2 = true;
    let mut first_handshake = true;

    loop {
        let handshake = server_handshake(&mut conn);
        let result = if first_handshake {
            first_handshake = false;
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "snell handshake timed out",
                    )
                    .into());
                }
            }
        } else {
            handshake.await
        };

        let (target, command) = match result {
            Ok(value) => value,
            Err(error) => {
                if !error.is_quiet() {
                    log::warn!("handshake failed: {error}");
                }
                break;
            }
        };

        if command != CMD_UDP {
            log::info!("new target: {target}");
        }

        match command {
            CMD_PING => {
                conn.snell_write(&[RESP_PONG]).await?;
                break;
            }
            CMD_CONNECT => {
                is_v2 = false;
                log::debug!("snell v1 connection");
            }
            CMD_CONNECT_V2 => {
                log::debug!("snell v2 connection");
            }
            CMD_UDP => {
                handle_udp_request(&mut conn).await?;
                break;
            }
            _ => {
                log::error!("unknown command 0x{command:x}");
                break;
            }
        }

        let target_stream = match TcpStream::connect(&target).await {
            Ok(stream) => stream,
            Err(error) => {
                write_error(&mut conn, &error.to_string()).await?;
                if !is_v2 {
                    break;
                }
                continue;
            }
        };

        conn.snell_write(&[RESP_TUNNEL]).await?;

        match relay_conn_to_tcp(&mut conn, target_stream, is_v2).await {
            Ok(()) => {
                // v2：目标 EOF 时的零分片已经发出，连接可直接用于下一个 CONNECT。
                if !is_v2 {
                    break;
                }
            }
            Err(error) => {
                if !error.is_quiet() {
                    log::warn!("relay to {target} ended with error: {error}");
                }
                break;
            }
        }
    }

    Ok(())
}

async fn server_handshake(conn: &mut SnellConn) -> Result<(String, u8), SnellError> {
    let mut buf = [0u8; 3];
    conn.snell_read(&mut buf).await?;

    if buf[0] != SNELL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid snell version 0x{:x}", buf[0]),
        )
        .into());
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

    let mut hlen_buf = [0u8; 1];
    conn.snell_read(&mut hlen_buf).await?;
    let hlen = hlen_buf[0] as usize;

    let mut host_port = vec![0u8; hlen + 2];
    conn.snell_read(&mut host_port).await?;

    let host = String::from_utf8_lossy(&host_port[..hlen]).to_string();
    let port = u16::from_be_bytes([host_port[hlen], host_port[hlen + 1]]);

    Ok((format!("{host}:{port}"), command))
}

async fn write_error(conn: &mut SnellConn, msg: &str) -> Result<(), SnellError> {
    let msg_bytes = msg.as_bytes();
    let truncated = &msg_bytes[..msg_bytes.len().min(250)];
    let mut buf = vec![RESP_ERROR, 0];
    buf.push(u8::try_from(truncated.len()).expect("truncated error message <= 250 bytes"));
    buf.extend_from_slice(truncated);
    conn.snell_write(&buf).await?;
    Ok(())
}

async fn handle_udp_request(conn: &mut SnellConn) -> Result<(), SnellError> {
    log::info!("new UDP request");

    let udp_sock = UdpSocket::bind("0.0.0.0:0").await?;
    conn.snell_write(&[RESP_READY]).await?;
    log::info!("UDP listening on: {}", udp_sock.local_addr()?);

    let mut cache = lru::LruCache::new(NonZeroUsize::new(256).expect("256 is non-zero"));
    let mut buf = vec![0u8; RELAY_BUF_SIZE];
    let mut udp_buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            read = conn.snell_read(&mut buf) => {
                let n = match read {
                    Ok(n) => n,
                    Err(error) if error.is_eof() => {
                        log::info!("UDP over TCP closed");
                        break;
                    }
                    Err(error) => return Err(error),
                };

                if n < 5 {
                    log::error!("UDP insufficient chunk size: {n} < 5");
                    break;
                }

                let cmd = buf[0];
                let hlen = buf[1];
                if cmd != CMD_UDP_FORWARD {
                    log::error!("UDP unknown command: 0x{cmd:x}");
                    break;
                }

                let (host, head) = if hlen == 0 {
                    let ip_ver = buf[2];
                    let iplen = match ip_ver {
                        4 => 4usize,
                        6 => 16usize,
                        _ => {
                            log::error!("unknown IP version: {ip_ver}");
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
                        IpAddr::V4(std::net::Ipv4Addr::new(
                            ip_bytes[0],
                            ip_bytes[1],
                            ip_bytes[2],
                            ip_bytes[3],
                        ))
                    } else {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(ip_bytes);
                        IpAddr::V6(std::net::Ipv6Addr::from(octets))
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

                let port = u16::from_be_bytes([buf[head], buf[head + 1]]);
                let target = format!("{host}:{port}");
                log::debug!("UDP over TCP forwarding to {target}");

                let uaddr = if let Some(&addr) = cache.get(&target) {
                    addr
                } else {
                    match tokio::net::lookup_host(&target).await {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                cache.put(target.clone(), addr);
                                addr
                            } else {
                                log::warn!("UDP failed to resolve {target}");
                                continue;
                            }
                        }
                        Err(error) => {
                            log::warn!("UDP failed to resolve {target}: {error}");
                            continue;
                        }
                    }
                };

                let payload_start = head + 2;
                if n > payload_start {
                    udp_sock.send_to(&buf[payload_start..n], uaddr).await?;
                }
            }
            recv = udp_sock.recv_from(&mut udp_buf) => {
                let (n, from) = match recv {
                    Ok(value) => value,
                    Err(error) => {
                        log::warn!("UDP recv error: {error}");
                        continue;
                    }
                };

                // 响应帧格式：[ipver(4|6)][addr][port_be][payload]
                let mut frame = Vec::with_capacity(n + 19);
                match from.ip() {
                    IpAddr::V4(ip) => {
                        frame.push(0x04);
                        frame.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        frame.push(0x06);
                        frame.extend_from_slice(&ip.octets());
                    }
                }
                frame.extend_from_slice(&from.port().to_be_bytes());
                frame.extend_from_slice(&udp_buf[..n]);

                if let Err(error) = conn.snell_write(&frame).await {
                    log::warn!("UDP response write error: {error}");
                    break;
                }
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
        log::info!(
            "SOCKS proxy listening at: {listen}, server: {}, obfs: {}, obfs_host: {}, snell_v{}",
            self.server,
            if self.obfs.is_empty() {
                "none"
            } else {
                &self.obfs
            },
            self.obfs_host,
            if self.is_v2 { 2 } else { 1 }
        );

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    log::warn!("accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let client = self.clone();
            tokio::spawn(async move {
                if let Err(error) = client.handle_socks_conn(stream).await {
                    if !error.is_quiet() {
                        log::warn!("socks connection error: {error}");
                    }
                }
            });
        }
    }

    async fn handle_socks_conn(&self, mut socks_stream: TcpStream) -> Result<(), SnellError> {
        let (addr, command) = socks5::server_handshake(&mut socks_stream).await?;

        match command {
            socks5::CMD_CONNECT => {}
            socks5::CMD_UDP_ASSOCIATE => {
                log::warn!("UDP ASSOCIATE is not supported");
                socks5::send_reply(&mut socks_stream, socks5::REP_COMMAND_NOT_SUPPORTED).await?;
                return Ok(());
            }
            _ => {
                socks5::send_reply(&mut socks_stream, socks5::REP_COMMAND_NOT_SUPPORTED).await?;
                return Ok(());
            }
        }

        let target = addr.to_string_addr().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed SOCKS5 target address",
            )
        })?;
        log::info!("new target: {target}");

        let mut snell_conn = match self.create_session(&target).await {
            Ok(conn) => conn,
            Err(error) => {
                let _ = socks5::send_reply(&mut socks_stream, socks5::REP_HOST_UNREACHABLE).await;
                return Err(error);
            }
        };

        let response = match snell_conn.read_response().await {
            Ok(response) => response,
            Err(error) => {
                let _ = socks5::send_reply(&mut socks_stream, socks5::REP_GENERAL_FAILURE).await;
                return Err(error);
            }
        };

        if response == RESP_ERROR {
            let message = snell_conn
                .read_error_response()
                .await
                .unwrap_or_else(|error| format!("<failed to read error: {error}>"));
            let _ = socks5::send_reply(&mut socks_stream, socks5::REP_HOST_UNREACHABLE).await;
            return Err(io::Error::other(format!("server error: {message}")).into());
        }
        if response != RESP_TUNNEL {
            let _ = socks5::send_reply(&mut socks_stream, socks5::REP_COMMAND_NOT_SUPPORTED).await;
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "unsupported server response").into(),
            );
        }

        socks5::send_reply(&mut socks_stream, socks5::REP_SUCCEEDED).await?;

        if let Err(error) = relay_tcp_to_conn(&mut socks_stream, &mut snell_conn, self.is_v2).await
        {
            if !error.is_quiet() {
                log::warn!("relay error: {error}");
            }
        }

        Ok(())
    }

    async fn create_session(&self, target: &str) -> Result<SnellConn, SnellError> {
        let stream = TcpStream::connect(&self.server).await?;
        let (_, server_port) = self
            .server
            .rsplit_once(':')
            .unwrap_or(("", self.server.as_str()));

        let mut conn = SnellConn::new_client_conn(
            stream,
            self.psk.as_bytes(),
            &self.obfs,
            &self.obfs_host,
            server_port,
            self.is_v2,
        );

        write_header(&mut conn, target, self.is_v2).await?;
        Ok(conn)
    }
}

async fn write_header(conn: &mut SnellConn, target: &str, is_v2: bool) -> Result<(), SnellError> {
    let (host, port_str) = target.rsplit_once(':').unwrap_or((target, "0"));
    let port: u16 = port_str.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid target port: {target}"),
        )
    })?;
    let host_len = u8::try_from(host.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("target host too long: {target}"),
        )
    })?;

    let mut buf = Vec::with_capacity(1 + 1 + 1 + 1 + host.len() + 2);
    buf.push(SNELL_VERSION);
    buf.push(if is_v2 { CMD_CONNECT_V2 } else { CMD_CONNECT });
    buf.push(0); // client ID length = 0
    buf.push(host_len);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());

    conn.snell_write(&buf).await?;
    Ok(())
}

// ---- Relay ----

/// 在 `SnellConn` 与目标 TCP 之间转发（服务端）。
///
/// v2 支持半关闭：客户端用零分片表示发送结束，服务端在目标 EOF 时发送一个零分片，
/// 两个方向都结束后连接仍可用于下一个请求。v1 没有半关闭，任一方向结束即关闭。
async fn relay_conn_to_tcp(
    snell: &mut SnellConn,
    target: TcpStream,
    is_v2: bool,
) -> Result<(), SnellError> {
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let mut snell_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut target_buf = vec![0u8; RELAY_BUF_SIZE];

    let mut snell_eof = false;
    let mut target_eof = false;

    loop {
        if is_v2 {
            if snell_eof && target_eof {
                break;
            }
        } else if snell_eof || target_eof {
            break;
        }

        tokio::select! {
            result = async {
                if snell_eof {
                    std::future::pending().await
                } else {
                    snell.snell_read(&mut snell_buf).await
                }
            } => {
                match result {
                    Ok(n) => target_write.write_all(&snell_buf[..n]).await?,
                    Err(error) if error.is_eof() => {
                        snell_eof = true;
                        let _ = target_write.shutdown().await;
                    }
                    Err(error) => return Err(error),
                }
            }
            result = async {
                if target_eof {
                    std::future::pending().await
                } else {
                    target_read.read(&mut target_buf).await
                }
            } => {
                match result {
                    Ok(0) => {
                        target_eof = true;
                        if is_v2 {
                            // 必须是 zero chunk：snell_eof 只代表对端方向结束，
                            // 客户端仍需要这个信号来结束自己的读方向。
                            snell.write_zero_chunk().await?;
                        }
                    }
                    Ok(n) => {
                        snell.snell_write(&target_buf[..n]).await?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        target_eof = true;
                        if is_v2 {
                            snell.write_zero_chunk().await?;
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    Ok(())
}

/// 在 SOCKS 客户端与 `SnellConn` 之间转发（客户端）。
///
/// v2 支持半关闭：SOCKS 侧 EOF 时向服务端发送零分片，但仍继续读取服务端数据，
/// 直到服务端也结束；v1 没有半关闭，任一方向结束即关闭。
async fn relay_tcp_to_conn(
    socks: &mut TcpStream,
    snell: &mut SnellConn,
    is_v2: bool,
) -> Result<(), SnellError> {
    let (mut socks_read, mut socks_write) = tokio::io::split(socks);

    let mut socks_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut snell_buf = vec![0u8; RELAY_BUF_SIZE];

    let mut socks_eof = false;
    let mut snell_eof = false;

    loop {
        if is_v2 {
            if socks_eof && snell_eof {
                break;
            }
        } else if socks_eof || snell_eof {
            break;
        }

        tokio::select! {
            result = async {
                if socks_eof {
                    std::future::pending().await
                } else {
                    socks_read.read(&mut socks_buf).await
                }
            } => {
                match result {
                    Ok(0) => {
                        socks_eof = true;
                        if is_v2 {
                            snell.write_zero_chunk().await?;
                        }
                    }
                    Ok(n) => {
                        snell.snell_write(&socks_buf[..n]).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            result = async {
                if snell_eof {
                    std::future::pending().await
                } else {
                    snell.snell_read(&mut snell_buf).await
                }
            } => {
                match result {
                    Ok(n) => socks_write.write_all(&snell_buf[..n]).await?,
                    Err(error) if error.is_eof() => {
                        snell_eof = true;
                        let _ = socks_write.shutdown().await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn pair(obfs: &str, is_v2: bool) -> (SnellConn, SnellConn) {
        let (client_stream, server_stream) = tcp_pair().await;

        let client = SnellConn::new_client_conn(
            client_stream,
            b"test-psk",
            obfs,
            "www.example.com",
            "443",
            is_v2,
        );
        let server = SnellConn::new_server_conn(server_stream, b"test-psk", obfs);
        (client, server)
    }

    #[tokio::test]
    async fn roundtrip_over_all_obfs_modes() {
        for obfs in ["", "tls", "http"] {
            let (mut client, mut server) = pair(obfs, true).await;

            client.snell_write(b"hello").await.unwrap();
            let mut buf = [0u8; 5];
            server.snell_read(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello", "client -> server over obfs {obfs:?}");

            server.snell_write(b"world").await.unwrap();
            let mut buf = [0u8; 5];
            client.snell_read(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world", "server -> client over obfs {obfs:?}");
        }
    }

    #[tokio::test]
    async fn zero_chunk_is_reported_as_stream_end() {
        let (mut client, mut server) = pair("", true).await;

        client.snell_write(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        server.snell_read(&mut buf).await.unwrap();

        client.write_zero_chunk().await.unwrap();
        let error = server.snell_read(&mut buf).await.unwrap_err();
        assert!(matches!(error, SnellError::ZeroChunk));
    }

    #[tokio::test]
    async fn large_payload_is_reassembled_across_records() {
        let (mut client, mut server) = pair("", true).await;
        let payload: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            client.snell_write(&payload).await.unwrap();
        });

        let mut received = Vec::with_capacity(expected.len());
        let mut chunk = [0u8; 1024];
        while received.len() < expected.len() {
            let n = server.snell_read(&mut chunk).await.unwrap();
            received.extend_from_slice(&chunk[..n]);
        }
        writer.await.unwrap();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn server_falls_back_to_chacha_for_v1_client() {
        let (mut client, mut server) = pair("", false).await;

        client.snell_write(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        server.snell_read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server.snell_write(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        client.snell_read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn server_relay_propagates_half_close() {
        let (mut client, mut snell_server) = pair("", true).await;
        let (mut target_client, target_server) = tcp_pair().await;

        let relay =
            tokio::spawn(
                async move { relay_conn_to_tcp(&mut snell_server, target_server, true).await },
            );

        client.snell_write(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        target_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        target_client.write_all(b"pong").await.unwrap();
        target_client.shutdown().await.unwrap();

        let mut buf = [0u8; 4];
        client.snell_read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        // 目标 EOF 后服务端发送零分片
        let error = client.snell_read(&mut buf).await.unwrap_err();
        assert!(matches!(error, SnellError::ZeroChunk));

        // 客户端半关闭后中继应正常结束
        client.write_zero_chunk().await.unwrap();
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn server_relay_signals_target_eof_after_client_half_close() {
        let (mut client, mut snell_server) = pair("", true).await;
        let (mut target_client, target_server) = tcp_pair().await;

        let relay =
            tokio::spawn(
                async move { relay_conn_to_tcp(&mut snell_server, target_server, true).await },
            );

        client.snell_write(b"request").await.unwrap();
        let mut buf = [0u8; 7];
        target_client.read_exact(&mut buf).await.unwrap();
        client.write_zero_chunk().await.unwrap();

        // 客户端先半关闭，目标稍后才 EOF：服务端仍必须发送 zero chunk
        target_client.write_all(b"response").await.unwrap();
        target_client.shutdown().await.unwrap();

        let mut buf = [0u8; 8];
        client.snell_read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"response");
        let error = client.snell_read(&mut buf).await.unwrap_err();
        assert!(matches!(error, SnellError::ZeroChunk));

        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_relay_keeps_reading_after_socks_half_close() {
        let (mut snell_client, mut snell_server) = pair("", true).await;
        let (mut socks_user, socks_proxy) = tcp_pair().await;

        let relay = tokio::spawn(async move {
            let mut socks_proxy = socks_proxy;
            relay_tcp_to_conn(&mut socks_proxy, &mut snell_client, true).await
        });

        socks_user.write_all(b"request").await.unwrap();
        let mut buf = [0u8; 7];
        snell_server.snell_read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"request");

        socks_user.shutdown().await.unwrap();
        let error = snell_server.snell_read(&mut buf).await.unwrap_err();
        assert!(matches!(error, SnellError::ZeroChunk));

        // 半关闭之后服务端仍可继续下发数据
        snell_server.snell_write(b"response").await.unwrap();
        let mut response = [0u8; 8];
        socks_user.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        // 服务端结束后，中继关闭 SOCKS 写方向
        snell_server.write_zero_chunk().await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(socks_user.read(&mut byte).await.unwrap(), 0);

        relay.await.unwrap().unwrap();
    }
}

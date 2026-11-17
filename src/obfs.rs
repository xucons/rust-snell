use std::cmp::min;
use std::io;

use rand::Rng;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TLS_CHUNK_SIZE: usize = 16 * 1024;
const READ_CHUNK: usize = 8192;
const MAX_OBFS_HEADER: usize = 8 * 1024;
const MAX_OBFS_BODY: usize = 64 * 1024;
const MAX_SKIPPED_RECORDS: usize = 8;
const RAW_COMPACT_THRESHOLD: usize = 16 * 1024;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_CLIENT_HELLO: u8 = 0x01;
const EXT_SESSION_TICKET: u16 = 0x0023;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMode {
    None,
    TlsServer,
    TlsClient,
    HttpServer,
    HttpClient,
}

pub struct ObfsState {
    mode: ObfsMode,
    host: String,
    port: String,
    first_read: bool,
    first_write: bool,
    ws_key: Option<String>,
    // 已从 TCP 读出、尚未被帧格式消费的原始字节
    raw: Vec<u8>,
    raw_pos: usize,
    // 已解帧、尚未交给调用方的字节
    decoded: Vec<u8>,
    dec_pos: usize,
}

impl ObfsState {
    pub fn new(mode: ObfsMode) -> Self {
        Self {
            mode,
            host: String::new(),
            port: String::new(),
            first_read: true,
            first_write: true,
            ws_key: None,
            raw: Vec::new(),
            raw_pos: 0,
            decoded: Vec::new(),
            dec_pos: 0,
        }
    }

    /// 客户端模式下设置伪装用的 Host / 端口。
    pub fn with_server(mut self, host: &str, port: &str) -> Self {
        self.host = host.to_string();
        self.port = port.to_string();
        self
    }

    /// 读取去混淆后的数据。
    ///
    /// 该函数可安全地被 `tokio::select!` 取消：所有从 socket 读出的字节都会先保存到
    /// `self.raw`，只有在数据完整后才会推进 `raw_pos` / 解密状态。
    pub async fn read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        if self.dec_pos < self.decoded.len() {
            return Ok(self.copy_decoded(buf));
        }
        self.decoded.clear();
        self.dec_pos = 0;

        match self.mode {
            ObfsMode::None => stream.read(buf).await,
            ObfsMode::HttpServer => self.http_read(stream, buf, true).await,
            ObfsMode::HttpClient => self.http_read(stream, buf, false).await,
            ObfsMode::TlsServer => {
                self.decoded = self.decode_tls_server(stream).await?;
                Ok(self.copy_decoded(buf))
            }
            ObfsMode::TlsClient => {
                self.decoded = self.decode_tls_client(stream).await?;
                Ok(self.copy_decoded(buf))
            }
        }
    }

    /// 写入带混淆封装的数据。
    pub async fn write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        match self.mode {
            ObfsMode::None => {
                stream.write_all(data).await?;
                Ok(data.len())
            }
            ObfsMode::TlsServer => self.tls_server_write(stream, data).await,
            ObfsMode::TlsClient => self.tls_client_write(stream, data).await,
            ObfsMode::HttpServer => self.http_server_write(stream, data).await,
            ObfsMode::HttpClient => self.http_client_write(stream, data).await,
        }
    }

    fn copy_decoded(&mut self, buf: &mut [u8]) -> usize {
        let n = min(buf.len(), self.decoded.len() - self.dec_pos);
        buf[..n].copy_from_slice(&self.decoded[self.dec_pos..self.dec_pos + n]);
        self.dec_pos += n;
        if self.dec_pos == self.decoded.len() {
            self.decoded.clear();
            self.dec_pos = 0;
        }
        n
    }

    // ---- 原始缓冲 ----

    fn buffered_raw(&self) -> usize {
        self.raw.len() - self.raw_pos
    }

    fn compact_raw(&mut self) {
        if self.raw_pos > 0
            && (self.raw_pos == self.raw.len() || self.raw_pos >= RAW_COMPACT_THRESHOLD)
        {
            self.raw.drain(..self.raw_pos);
            self.raw_pos = 0;
        }
    }

    fn copy_raw(&mut self, buf: &mut [u8]) -> usize {
        let n = min(buf.len(), self.buffered_raw());
        buf[..n].copy_from_slice(&self.raw[self.raw_pos..self.raw_pos + n]);
        self.raw_pos += n;
        self.compact_raw();
        n
    }

    fn take_raw(&mut self, n: usize) -> Vec<u8> {
        let start = self.raw_pos;
        self.raw_pos += n;
        let out = self.raw[start..start + n].to_vec();
        self.compact_raw();
        out
    }

    /// 确保缓冲中至少有 `n` 个未消费字节。唯一的 await 是 `TcpStream::read`（取消安全）。
    async fn fill_raw(&mut self, stream: &mut TcpStream, n: usize) -> io::Result<()> {
        while self.buffered_raw() < n {
            let mut chunk = [0u8; READ_CHUNK];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            self.raw.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    // ---- TLS ----

    async fn read_tls_record(&mut self, stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
        self.fill_raw(stream, 5).await?;
        let record_type = self.raw[self.raw_pos];
        let length =
            u16::from_be_bytes([self.raw[self.raw_pos + 3], self.raw[self.raw_pos + 4]]) as usize;
        // 先确保整条记录到齐再推进游标，避免取消后把 payload 当成新的记录头
        self.fill_raw(stream, 5 + length).await?;
        self.raw_pos += 5;
        Ok((record_type, self.take_raw(length)))
    }

    async fn decode_tls_server(&mut self, stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        if self.first_read {
            let (record_type, record) = self.read_tls_record(stream).await?;
            if record_type != TLS_HANDSHAKE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected TLS ClientHello record",
                ));
            }
            let session_ticket = parse_client_hello_ticket(&record)?;
            self.first_read = false;
            Ok(session_ticket)
        } else {
            let (_, payload) = self.read_tls_record(stream).await?;
            Ok(payload)
        }
    }

    async fn decode_tls_client(&mut self, stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        if self.first_read {
            for _ in 0..MAX_SKIPPED_RECORDS {
                let (record_type, payload) = self.read_tls_record(stream).await?;
                if record_type == TLS_APPLICATION_DATA {
                    self.first_read = false;
                    return Ok(payload);
                }
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no TLS application data record in server handshake",
            ))
        } else {
            let (_, payload) = self.read_tls_record(stream).await?;
            Ok(payload)
        }
    }

    async fn tls_server_write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let server_hello = make_server_hello(data);
            stream.write_all(&server_hello).await?;
            Ok(data.len())
        } else {
            Self::tls_write_app_data(stream, data).await
        }
    }

    async fn tls_client_write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let hello = make_client_hello(data, &self.host);
            stream.write_all(&hello).await?;
            Ok(data.len())
        } else {
            Self::tls_write_app_data(stream, data).await
        }
    }

    async fn tls_write_app_data(stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        let data_len = data.len();
        let mut written = 0;
        while written < data_len {
            let end = min(written + TLS_CHUNK_SIZE, data_len);
            let chunk = &data[written..end];
            let len = u16::try_from(chunk.len()).expect("TLS chunk fits in u16");
            let mut header = [0x17, 0x03, 0x03, 0, 0];
            header[3..].copy_from_slice(&len.to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(chunk).await?;
            written = end;
        }
        Ok(data_len)
    }

    // ---- HTTP ----

    async fn http_read(
        &mut self,
        stream: &mut TcpStream,
        buf: &mut [u8],
        server: bool,
    ) -> io::Result<usize> {
        if self.first_read {
            let headers = self.read_http_headers(stream).await?;
            self.first_read = false;

            if server {
                if let Some(key) = header_value(&headers, "sec-websocket-key") {
                    self.ws_key = Some(key.to_string());
                }
                let content_length = extract_content_length(&headers).unwrap_or(0);
                if content_length > MAX_OBFS_BODY {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "obfs request body too large",
                    ));
                }
                if content_length > 0 {
                    self.fill_raw(stream, content_length).await?;
                    return Ok(self.copy_raw(buf));
                }
                return Ok(0);
            }
            // 101 响应没有 Content-Length：header 之后直接就是数据
        }
        self.http_passthrough(stream, buf).await
    }

    async fn http_passthrough(
        &mut self,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if self.buffered_raw() > 0 {
            return Ok(self.copy_raw(buf));
        }
        stream.read(buf).await
    }

    async fn read_http_headers(&mut self, stream: &mut TcpStream) -> io::Result<String> {
        loop {
            if let Some(index) = find_crlfcrlf(&self.raw[self.raw_pos..]) {
                let total = index + 4;
                let headers =
                    String::from_utf8_lossy(&self.raw[self.raw_pos..self.raw_pos + total])
                        .into_owned();
                self.raw_pos += total;
                self.compact_raw();
                return Ok(headers);
            }
            if self.buffered_raw() >= MAX_OBFS_HEADER {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "obfs HTTP header too large",
                ));
            }
            self.fill_raw(stream, self.buffered_raw() + 1).await?;
        }
    }

    async fn http_server_write(
        &mut self,
        stream: &mut TcpStream,
        data: &[u8],
    ) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let ws_accept = if let Some(key) = self.ws_key.take() {
                websocket_accept(&key)
            } else {
                let mut random = [0u8; 16];
                rand::thread_rng().fill(&mut random);
                base64_encode(&random)
            };
            let (version_major, version_minor) = {
                let mut rng = rand::thread_rng();
                (rng.gen_range(0..11usize), rng.gen_range(0..12usize))
            };
            let http_date = http_date_rfc1123();
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Server: nginx/1.{version_major}.{version_minor}\r\n\
                 Date: {http_date}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {ws_accept}\r\n\
                 \r\n"
            );
            stream.write_all(resp.as_bytes()).await?;
            stream.write_all(data).await?;
            Ok(data.len())
        } else {
            stream.write_all(data).await?;
            Ok(data.len())
        }
    }

    async fn http_client_write(
        &mut self,
        stream: &mut TcpStream,
        data: &[u8],
    ) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let host = &self.host;
            let port = &self.port;
            let mut random = [0u8; 16];
            rand::thread_rng().fill(&mut random);
            let ws_key = base64_encode(&random);
            let (curl_minor, curl_patch) = {
                let mut rng = rand::thread_rng();
                (rng.gen_range(0..54usize), rng.gen_range(0..2usize))
            };
            let data_len = data.len();
            let req = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {host}:{port}\r\n\
                 User-Agent: curl/7.{curl_minor}.{curl_patch}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {ws_key}\r\n\
                 Content-Length: {data_len}\r\n\
                 \r\n"
            );
            stream.write_all(req.as_bytes()).await?;
            stream.write_all(data).await?;
            Ok(data.len())
        } else {
            stream.write_all(data).await?;
            Ok(data.len())
        }
    }
}

fn find_crlfcrlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        if header_name.eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn extract_content_length(headers: &str) -> Option<usize> {
    header_value(headers, "content-length")?.parse().ok()
}

/// 按 TLS 记录结构解析 `ClientHello`，并取出 `SessionTicket` 扩展中的数据（即 Snell salt）。
fn parse_client_hello_ticket(record: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = Cursor::new(record);
    if cursor.u8()? != TLS_CLIENT_HELLO {
        return Err(truncated("expected TLS ClientHello handshake"));
    }
    let handshake_len = cursor.u24()? as usize;
    let body = cursor.take(handshake_len)?;

    let mut cursor = Cursor::new(body);
    cursor.skip(2)?; // version
    cursor.skip(32)?; // random
    let session_id_len = cursor.u8()? as usize;
    cursor.skip(session_id_len)?;
    let cipher_suites_len = cursor.u16()? as usize;
    cursor.skip(cipher_suites_len)?;
    let compression_len = cursor.u8()? as usize;
    cursor.skip(compression_len)?;
    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;

    let mut cursor = Cursor::new(extensions);
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16()?;
        let item_len = cursor.u16()? as usize;
        let data = cursor.take(item_len)?;
        if extension_type == EXT_SESSION_TICKET {
            return Ok(data.to_vec());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "ClientHello has no session ticket extension",
    ))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn u8(&mut self) -> io::Result<u8> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> io::Result<u32> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.take(n).map(|_| ())
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(truncated("truncated TLS handshake"));
        }
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }
}

fn truncated(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64_encode(&hasher.finalize())
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn http_date_rfc1123() -> String {
    let now = std::time::SystemTime::now();
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let (year, month, day) = days_to_date(days_since_epoch);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday =
        ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][((4 + days_since_epoch) % 7) as usize];
    let month_name = months[usize::try_from(month - 1).expect("month is in 1..=12")];
    format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (index, &days) in month_days.iter().enumerate() {
        if remaining < days {
            month = index;
            break;
        }
        remaining -= days;
    }
    (year, (month + 1) as u64, remaining + 1)
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn make_server_hello(data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut rand_bytes = [0u8; 28];
    let mut session_id = [0u8; 32];
    rng.fill(&mut rand_bytes);
    rng.fill(&mut session_id);

    let mut buf = Vec::with_capacity(107 + data.len());

    // ServerHello handshake record
    buf.push(0x16); // handshake
    buf.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0
    buf.extend_from_slice(&91u16.to_be_bytes()); // length = 91

    buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x57]); // ServerHello, length=87
    buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    let ts = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(u32::MAX);
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(&rand_bytes);
    buf.push(32); // session ID length
    buf.extend_from_slice(&session_id);

    buf.extend_from_slice(&[0xcc, 0xa8]); // cipher suite
    buf.push(0x00); // compression
    buf.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

    buf.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation info
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]); // ec_point_formats

    // ChangeCipherSpec
    buf.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // Application data record carrying the Snell salt
    buf.extend_from_slice(&[0x17, 0x03, 0x03]);
    let len = u16::try_from(data.len()).expect("salt fits in one TLS record");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);

    buf
}

fn make_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rng.fill(&mut random);
    rng.fill(&mut session_id);

    let server_bytes = server.as_bytes();
    let data_len = u16::try_from(data.len()).expect("session ticket data fits in u16");
    let server_len = u16::try_from(server_bytes.len()).expect("SNI host fits in u16");
    let ext_len = u16::try_from(79 + data.len() + server_bytes.len())
        .expect("ClientHello extensions fit in u16");
    let hs_len = ext_len.checked_add(129).expect("ClientHello fits in u16");
    let record_len = hs_len.checked_add(4).expect("TLS record fits in u16");

    let mut buf = Vec::with_capacity(5 + usize::from(record_len));

    // Record header
    buf.push(22); // handshake
    buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    buf.extend_from_slice(&record_len.to_be_bytes());

    // ClientHello
    buf.push(0x01);
    buf.extend_from_slice(&[0x00]);
    buf.extend_from_slice(&hs_len.to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random with timestamp
    let ts = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(u32::MAX);
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(&random);

    // Session ID
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // Cipher suites
    buf.extend_from_slice(&[0x00, 0x38]); // length = 56
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // Compression
    buf.extend_from_slice(&[0x01, 0x00]);

    // Extensions length
    buf.extend_from_slice(&ext_len.to_be_bytes());

    // Session ticket extension (carries the Snell salt)
    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&data_len.to_be_bytes());
    buf.extend_from_slice(data);

    // SNI extension
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&(server_len + 5).to_be_bytes());
    buf.extend_from_slice(&(server_len + 3).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&server_len.to_be_bytes());
    buf.extend_from_slice(server_bytes);

    // ec_point_formats
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // supported_groups
    buf.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);

    // signature_algorithms
    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt_then_mac
    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended_master_secret
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_uses_standard_alphabet() {
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn content_length_parsing_is_case_insensitive() {
        assert_eq!(extract_content_length("Content-Length: 12\r\n"), Some(12));
        assert_eq!(extract_content_length("content-length: 7\r\n"), Some(7));
        assert_eq!(extract_content_length("Content-Length: nope\r\n"), None);
        assert_eq!(extract_content_length("Host: example.com\r\n"), None);
    }

    #[test]
    fn client_hello_session_ticket_roundtrip() {
        let salt = b"0123456789abcdef";
        let hello = make_client_hello(salt, "www.example.com");
        let ticket = parse_client_hello_ticket(&hello[5..]).unwrap();
        assert_eq!(ticket, salt);
    }

    #[test]
    fn truncated_client_hello_is_rejected() {
        let salt = b"0123456789abcdef";
        let hello = make_client_hello(salt, "www.example.com");
        let truncated_record = &hello[5..hello.len() - 3];
        assert!(parse_client_hello_ticket(truncated_record).is_err());
    }

    #[test]
    fn crlfcrlf_detection() {
        assert_eq!(find_crlfcrlf(b"abc\r\n\r\nxyz"), Some(3));
        assert_eq!(find_crlfcrlf(b"abc\r\n"), None);
    }

    #[test]
    fn rfc1123_date_is_well_formed() {
        let date = http_date_rfc1123();
        assert!(date.ends_with("GMT"));
        assert!(date.contains(", "));
    }
}

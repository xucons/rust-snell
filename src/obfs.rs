use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use rand::Rng;

const TLS_CHUNK_SIZE: usize = 16 * 1024;

#[derive(Debug)]
pub enum ObfsMode {
    None,
    TlsServer,
    TlsClient { host: String },
    HttpServer,
    HttpClient { host: String, port: String },
}

pub struct ObfsState {
    mode: ObfsMode,
    first_read: bool,
    first_write: bool,
    tls_session_ticket_done: bool,
    tls_remain: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ObfsState {
    pub fn new(mode: ObfsMode) -> Self {
        Self {
            mode,
            first_read: true,
            first_write: true,
            tls_session_ticket_done: false,
            tls_remain: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Read de-obfuscated data. Returns bytes copied into `buf`.
    /// For TLS obfs: strips TLS record headers.
    /// For HTTP obfs: handles initial HTTP handshake.
    /// For None: reads directly from TCP.
    pub async fn read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        // Drain buffered data first
        if self.read_pos < self.read_buf.len() {
            let n = std::cmp::min(buf.len(), self.read_buf.len() - self.read_pos);
            buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Ok(n);
        }

        match self.mode {
            ObfsMode::None => {
                stream.read(buf).await
            }
            ObfsMode::TlsServer => {
                self.tls_server_read(stream, buf).await
            }
            ObfsMode::TlsClient { .. } => {
                self.tls_client_read(stream, buf).await
            }
            ObfsMode::HttpServer => {
                self.http_server_read(stream, buf).await
            }
            ObfsMode::HttpClient { .. } => {
                self.http_client_read(stream, buf).await
            }
        }
    }

    /// Write data with obfuscation framing.
    /// For TLS obfs: wraps in TLS records.
    /// For HTTP obfs: wraps first write in HTTP request/response.
    /// For None: writes directly to TCP.
    pub async fn write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        match self.mode {
            ObfsMode::None => {
                stream.write_all(data).await?;
                Ok(data.len())
            }
            ObfsMode::TlsServer => {
                self.tls_server_write(stream, data).await
            }
            ObfsMode::TlsClient { ref host } => {
                let host = host.clone();
                self.tls_client_write(stream, data, &host).await
            }
            ObfsMode::HttpServer => {
                self.http_server_write(stream, data).await
            }
            ObfsMode::HttpClient { ref host, ref port } => {
                let host = host.clone();
                let port = port.clone();
                self.http_client_write(stream, data, &host, &port).await
            }
        }
    }

    // ---- TLS Server ----

    async fn tls_server_read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        if self.tls_remain > 0 {
            let n = std::cmp::min(buf.len(), self.tls_remain);
            stream.read_exact(&mut buf[..n]).await?;
            self.tls_remain -= n;
            return Ok(n);
        }

        if self.first_read {
            self.first_read = false;
            // Skip 140 bytes of ClientHello header, then read session ticket data
            let mut skip = vec![0u8; 140];
            stream.read_exact(&mut skip).await?;
            // Read 2-byte length
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let length = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
            if length <= buf.len() {
                stream.read_exact(&mut buf[..length]).await?;
                Ok(length)
            } else {
                let n = stream.read(buf).await?;
                self.tls_remain = length - n;
                Ok(n)
            }
        } else if !self.tls_session_ticket_done {
            self.tls_session_ticket_done = true;
            // Skip SNI extension: skip 7 bytes, read a record block, then skip remaining extensions
            let mut skip = vec![0u8; 7];
            stream.read_exact(&mut skip).await?;
            // Read SNI name length + name
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let sni_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
            let mut sni_data = vec![0u8; sni_len];
            stream.read_exact(&mut sni_data).await?;
            // Skip remaining extensions
            let mut ext = vec![0u8; 4 * 16 + 2];
            stream.read_exact(&mut ext).await?;
            // Now read the first Application Data record
            self.tls_read_record(stream, buf).await
        } else {
            // Normal: skip 3-byte TLS record header, read record
            self.tls_read_record(stream, buf).await
        }
    }

    async fn tls_read_record(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        let mut header = [0u8; 3]; // type + version
        stream.read_exact(&mut header).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let length = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
        if length <= buf.len() {
            stream.read_exact(&mut buf[..length]).await?;
            Ok(length)
        } else {
            let n = stream.read(buf).await?;
            self.tls_remain = length - n;
            Ok(n)
        }
    }

    async fn tls_server_write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let server_hello = make_server_hello(data);
            stream.write_all(&server_hello).await?;
            Ok(data.len())
        } else {
            self.tls_write_app_data(stream, data).await
        }
    }

    async fn tls_write_app_data(&self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        let data_len = data.len();
        let mut written = 0;
        while written < data_len {
            let end = std::cmp::min(written + TLS_CHUNK_SIZE, data_len);
            let chunk = &data[written..end];
            let mut header = vec![0x17, 0x03, 0x03];
            let len = chunk.len() as u16;
            header.extend_from_slice(&len.to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(chunk).await?;
            written = end;
        }
        Ok(data_len)
    }

    // ---- TLS Client ----

    async fn tls_client_read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        if self.tls_remain > 0 {
            let n = std::cmp::min(buf.len(), self.tls_remain);
            stream.read_exact(&mut buf[..n]).await?;
            self.tls_remain -= n;
            return Ok(n);
        }

        if self.first_read {
            self.first_read = false;
            // Skip 105 bytes of ServerHello + CCS + record header
            let mut skip = vec![0u8; 105];
            stream.read_exact(&mut skip).await?;
            // Read 2-byte length
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let length = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
            if length <= buf.len() {
                stream.read_exact(&mut buf[..length]).await?;
                Ok(length)
            } else {
                let n = stream.read(buf).await?;
                self.tls_remain = length - n;
                Ok(n)
            }
        } else {
            // Normal: skip 3-byte header, read record
            let mut header = [0u8; 3];
            stream.read_exact(&mut header).await?;
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let length = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
            if length <= buf.len() {
                stream.read_exact(&mut buf[..length]).await?;
                Ok(length)
            } else {
                let n = stream.read(buf).await?;
                self.tls_remain = length - n;
                Ok(n)
            }
        }
    }

    async fn tls_client_write(&mut self, stream: &mut TcpStream, data: &[u8], server: &str) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let hello = make_client_hello(data, server);
            stream.write_all(&hello).await?;
            Ok(data.len())
        } else {
            self.tls_write_app_data(stream, data).await
        }
    }

    // ---- HTTP Server ----

    async fn http_server_read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        if self.first_read {
            self.first_read = false;
            // Read HTTP request until \r\n\r\n
            let mut headers = Vec::new();
            let mut prev = [0u8; 4];
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await?;
                headers.push(byte[0]);
                prev[0] = prev[1];
                prev[1] = prev[2];
                prev[2] = prev[3];
                prev[3] = byte[0];
                if prev == [b'\r', b'\n', b'\r', b'\n'] {
                    break;
                }
            }

            let header_str = String::from_utf8_lossy(&headers);
            // Find Content-Length
            let content_length = extract_content_length(&header_str).unwrap_or(0);

            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                stream.read_exact(&mut body).await?;
                let n = std::cmp::min(buf.len(), body.len());
                buf[..n].copy_from_slice(&body[..n]);
                if body.len() > buf.len() {
                    self.read_buf = body[buf.len()..].to_vec();
                    self.read_pos = 0;
                }
                Ok(n)
            } else {
                Ok(0)
            }
        } else {
            stream.read(buf).await
        }
    }

    async fn http_server_write(&mut self, stream: &mut TcpStream, data: &[u8]) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let (ws_accept, now, v_major, v_minor) = {
                let mut rng = rand::thread_rng();
                let mut rand_bytes = [0u8; 16];
                rng.fill(&mut rand_bytes);
                let ws_accept = base64_url_encode(&rand_bytes);
                let now = chrono_now_rfc1123();
                let v_major: usize = rng.gen_range(0..11);
                let v_minor: usize = rng.gen_range(0..12);
                (ws_accept, now, v_major, v_minor)
            };
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Server: nginx/1.{}.{}\r\n\
                 Date: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                v_major, v_minor, now, ws_accept
            );
            stream.write_all(resp.as_bytes()).await?;
            stream.write_all(data).await?;
            Ok(data.len())
        } else {
            stream.write_all(data).await?;
            Ok(data.len())
        }
    }

    // ---- HTTP Client ----

    async fn http_client_read(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        if self.first_read {
            self.first_read = false;
            // Read HTTP response until \r\n\r\n
            let mut headers = Vec::new();
            let mut prev = [0u8; 4];
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await?;
                headers.push(byte[0]);
                prev[0] = prev[1];
                prev[1] = prev[2];
                prev[2] = prev[3];
                prev[3] = byte[0];
                if prev == [b'\r', b'\n', b'\r', b'\n'] {
                    break;
                }
            }

            let header_str = String::from_utf8_lossy(&headers);
            let content_length = extract_content_length(&header_str).unwrap_or(0);

            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                stream.read_exact(&mut body).await?;
                let n = std::cmp::min(buf.len(), body.len());
                buf[..n].copy_from_slice(&body[..n]);
                if body.len() > buf.len() {
                    self.read_buf = body[buf.len()..].to_vec();
                    self.read_pos = 0;
                }
                Ok(n)
            } else {
                Ok(0)
            }
        } else {
            stream.read(buf).await
        }
    }

    async fn http_client_write(&mut self, stream: &mut TcpStream, data: &[u8], host: &str, port: &str) -> io::Result<usize> {
        if self.first_write {
            self.first_write = false;
            let (ws_key, curl_minor, curl_patch, data_len) = {
                let mut rng = rand::thread_rng();
                let mut rand_bytes = [0u8; 16];
                rng.fill(&mut rand_bytes);
                let ws_key = base64_url_encode(&rand_bytes);
                let curl_minor: usize = rng.gen_range(0..54);
                let curl_patch: usize = rng.gen_range(0..2);
                (ws_key, curl_minor, curl_patch, data.len())
            };
            let req = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 User-Agent: curl/7.{}.{}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Content-Length: {}\r\n\
                 \r\n",
                host, port, curl_minor, curl_patch, ws_key, data_len
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

fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some(stripped) = line.strip_prefix("Content-Length:") {
            return stripped.trim().parse().ok();
        }
        if let Some(stripped) = line.strip_prefix("content-length:") {
            return stripped.trim().parse().ok();
        }
    }
    None
}

fn base64_url_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.write_char(TABLE[((triple >> 18) & 0x3F) as usize] as char).unwrap();
        out.write_char(TABLE[((triple >> 12) & 0x3F) as usize] as char).unwrap();
        if chunk.len() > 1 {
            out.write_char(TABLE[((triple >> 6) & 0x3F) as usize] as char).unwrap();
        }
        if chunk.len() > 2 {
            out.write_char(TABLE[(triple & 0x3F) as usize] as char).unwrap();
        }
    }
    out
}

fn chrono_now_rfc1123() -> String {
    // Simple RFC1123 date without chrono dependency
    let now = std::time::SystemTime::now();
    let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Calculate date from days since epoch
    let (year, month, day) = days_to_date(days_since_epoch);
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][((4 + days_since_epoch) % 7) as usize];
    format!("{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT", weekday, day, months[month as usize - 1], year, hour, minute, second)
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for (i, &d) in month_days.iter().enumerate() {
        if remaining < d {
            m = i;
            break;
        }
        remaining -= d;
    }
    (y, (m + 1) as u64, remaining + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
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

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
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

    // Handshake record with data
    buf.extend_from_slice(&[0x16, 0x03, 0x03]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    buf
}

fn make_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rng.fill(&mut random);
    rng.fill(&mut session_id);

    let data_len = data.len() as u16;
    let server_bytes = server.as_bytes();
    let server_len = server_bytes.len() as u16;
    let ext_len = (79 + data.len() + server_bytes.len()) as u16;
    let hs_len = (208 + data.len() + server_bytes.len()) as u16;
    let record_len = (212 + data.len() + server_bytes.len()) as u16;

    let mut buf = Vec::with_capacity(5 + record_len as usize);

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
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(&random);

    // Session ID
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // Cipher suites
    buf.extend_from_slice(&[0x00, 0x38]); // length = 56
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // Compression
    buf.extend_from_slice(&[0x01, 0x00]);

    // Extensions length
    buf.extend_from_slice(&ext_len.to_be_bytes());

    // Session ticket extension
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
    buf.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18]);

    // signature_algorithms
    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
        0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
        0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt_then_mac
    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended_master_secret
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

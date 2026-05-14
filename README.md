# rust-snell

Snell 协议的 Rust 实现，支持 TLS/HTTP 流量混淆与多路复用。

## 功能特性

- Snell v1（ChaCha20-Poly1305）与 v2（AES-128-GCM）协议支持
- TLS / HTTP 流量混淆，伪装为正常 HTTPS 或 WebSocket 流量
- v2 多路复用：同一 Snell 连接可复用于多个目标
- 服务端自动密码套件回退：优先 AES-128-GCM，首次解密失败自动切换 ChaCha20-Poly1305
- 客户端内置 SOCKS5 代理，支持 CONNECT 和 UDP ASSOCIATE
- 基于 tokio 的异步 I/O，全异步实现
- 支持 INI 格式配置文件与命令行参数两种配置方式

## 编译

```bash
cargo build --release
```

编译产物位于 `target/release/rust-snell`。

## 使用方法

### 服务端

```bash
# 基本用法
rust-snell --server -k <预共享密钥>

# 指定监听地址与 TLS 混淆
rust-snell --server -l 0.0.0.0:12345 -k <预共享密钥> --obfs tls

# 使用配置文件
rust-snell --server -c /path/to/config.ini
```

### 客户端

```bash
# 基本用法（默认 Snell v2）
rust-snell -s <服务器地址:端口> -k <预共享密钥>

# 指定本地 SOCKS5 监听地址与 HTTP 混淆
rust-snell -l 127.0.0.1:1080 -s <服务器地址:端口> -k <预共享密钥> --obfs http

# 使用 Snell v1
rust-snell -s <服务器地址:端口> -k <预共享密钥> -v 1
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--server` | 以服务端模式运行（仅服务端） | 客户端模式 |
| `-c <路径>` | 配置文件路径 | — |
| `-l <地址>` | 监听地址 | `0.0.0.0:18888` |
| `-s <地址>` | 服务器地址（仅客户端） | — |
| `-k <密钥>` | 预共享密钥（PSK） | — |
| `--obfs <类型>` | 混淆类型：`tls`、`http` 或留空 | 空（不混淆） |
| `--obfs-host <域名>` | 混淆伪装域名 | `bing.com` |
| `-v <版本>` | Snell 协议版本（1 或 2，仅客户端） | `2` |
| `--version` | 显示版本号 | — |

### 配置文件

使用 INI 格式，通过 `[snell-server]` 或 `[snell-client]` 区分段落，`parse_file_auto` 会自动检测使用哪个段落：

**服务端配置示例** (`server.ini`)：

```ini
[snell-server]
listen = 0.0.0.0:12345
psk = your-secret-key
obfs = tls
```

**客户端配置示例** (`client.ini`)：

```ini
[snell-client]
listen = 127.0.0.1:1080
server = your-server:12345
psk = your-secret-key
obfs = http
obfs-host = www.bing.com
version = 2
```

## 架构

### 数据流

```
客户端模式：应用 → SOCKS5 → [SnellClient] → 混淆层 → AEAD 加密 → TCP → 服务器
服务端模式：客户端 → TCP → AEAD 解密 → 混淆层 → [SnellConn] → 目标 TCP
```

### 模块说明

| 模块 | 说明 |
|------|------|
| `main.rs` | CLI 参数解析（clap）、配置加载、模式分发 |
| `config.rs` | INI 配置文件解析，支持自动检测 `[snell-server]`/`[snell-client]` 段落 |
| `snell.rs` | 核心协议逻辑：`SnellConn` 封装 TCP 流 + AEAD + 混淆层，处理 Snell 握手、v1/v2 多路复用、UDP 中继、双向数据转发 |
| `aead.rs` | AEAD 加密抽象：AES-128-GCM（v2）与 ChaCha20-Poly1305（v1），密钥派生使用 Argon2id |
| `obfs.rs` | 流量混淆：伪装为 TLS 1.2 握手或 HTTP WebSocket 升级请求 |
| `socks5.rs` | SOCKS5 协议握手，支持 CONNECT 和 UDP ASSOCIATE 命令，地址编码支持 IPv4/IPv6/域名 |

### 协议细节

- **Snell v1**：使用 ChaCha20-Poly1305，无多路复用，每个 SOCKS 请求对应一个独立连接，数据转发完毕后连接关闭。
- **Snell v2**：使用 AES-128-GCM，支持多路复用，数据转发完毕后双方交换零长度分片（zero chunk），连接保持开放，可在同一 Snell 会话上复用于下一个目标。
- **服务端密码回退**：服务端默认使用 AES-128-GCM 作为主密码套件，ChaCha20-Poly1305 作为回退。若首个 AEAD 记录解密失败，自动切换至回退套件。
- **零长度分片**：v2 中以零长度载荷加密为一条 AEAD 记录，作为流结束信号。

## 依赖

- [tokio](https://tokio.rs/) — 异步运行时
- [aes-gcm](https://crates.io/crates/aes-gcm) — AES-128-GCM 加密
- [chacha20poly1305](https://crates.io/crates/chacha20poly1305) — ChaCha20-Poly1305 加密
- [argon2](https://crates.io/crates/argon2) — Argon2id 密钥派生
- [clap](https://crates.io/crates/clap) — 命令行参数解析

## 许可证

MIT

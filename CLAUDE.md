# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
cargo build                          # debug build
cargo build --release                # release build (binary at target/release/rust-snell)
cargo run -- --server -k <PSK>       # run as server
cargo run -- -s <ADDR:PORT> -k <PSK> # run as client
cargo test                           # run tests (none currently)
```

CLI flags: `--server`, `-c <config>`, `-l <listen>`, `-s <server_addr>`, `-k <psk>`, `--obfs <tls|http|>`, `--obfs-host <host>`, `-v <1|2>`, `--version`.

## Architecture

This is a Rust implementation of the **Snell protocol** — an encrypted proxy protocol with TLS/HTTP obfuscation. It runs in two modes: **server** (accepts Snell connections, relays to targets) and **client** (exposes a local SOCKS5 proxy, forwards to a Snell server).

### Data flow

```
Client mode:  App → SOCKS5 → [SnellClient] → Obfs → AEAD → TCP → Server
Server mode:  Client → TCP → AEAD → Obfs → [SnellConn] → Target TCP
```

### Module breakdown

- **`main.rs`** — CLI parsing (clap), config loading, mode dispatch. PSK is always required.
- **`config.rs`** — INI-style config file parser with `[snell-server]`/`[snell-client]` sections. `parse_file_auto` detects which section exists.
- **`snell.rs`** — Core protocol logic. `SnellConn` wraps a TCP stream with AEAD + obfuscation layers. Handles the Snell handshake, v1/v2 multiplexing (zero-chunk signaling), UDP relay, and bidirectional data relay using `tokio::select!`.
- **`aead.rs`** — AEAD encryption abstraction. Two ciphers: `Aes128Gcm` (v2) and `ChaCha20Poly1305` (v1). Key derivation uses Argon2id (`snell_kdf`). Server tries both ciphers on first record and falls back if the primary fails.
- **`obfs.rs`** — Traffic obfuscation. `ObfsState` wraps reads/writes to make traffic look like TLS 1.2 or HTTP WebSocket upgrades. TLS mode constructs/extracts fake ClientHello/ServerHello records. HTTP mode wraps first payload in a WebSocket-style HTTP request/response.
- **`socks5.rs`** — SOCKS5 handshake for the client's local listener. Supports CONNECT and UDP ASSOCIATE commands. `SocksAddr` handles the SOCKS5 address encoding (IPv4/IPv6/domain).

### Key protocol details

- **Snell v1**: Uses ChaCha20-Poly1305, no multiplexing — one connection per SOCKS request, connection closes after relay ends.
- **Snell v2**: Uses AES-128-GCM by default, supports multiplexing — after relay ends, both sides exchange zero chunks, then the connection stays open for the next target on the same Snell session.
- **Server cipher fallback**: Server starts with AES-128-GCM as primary, ChaCha20-Poly1305 as fallback. If the first AEAD header decrypt fails with the primary, it switches to the fallback permanently for that connection.
- **Zero chunks**: A zero-length payload encrypted as an AEAD record signals end-of-stream in v2. Received as `ZeroChunkError` internally.

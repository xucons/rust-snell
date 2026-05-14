mod aead;
mod config;
mod obfs;
mod snell;
mod socks5;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rust-snell", about = "A Snell protocol implementation in Rust")]
struct Args {
    /// Run as server (server only)
    #[arg(long)]
    server: bool,

    /// Configuration file path
    #[arg(short = 'c')]
    config: Option<String>,

    /// Listen address
    #[arg(short = 'l', default_value = "0.0.0.0:18888")]
    listen: String,

    /// Server address (client only)
    #[arg(short = 's')]
    server_addr: Option<String>,

    /// Pre-shared key
    #[arg(short = 'k')]
    psk: Option<String>,

    /// Obfuscation type (tls, http, or empty)
    #[arg(long, default_value = "")]
    obfs: String,

    /// Obfuscation host
    #[arg(long, default_value = "bing.com")]
    obfs_host: String,

    /// Snell version (1 or 2, client only)
    #[arg(short = 'v', long = "snell-version", default_value = "2")]
    snell_version: String,

    /// Show version
    #[arg(long)]
    version: bool,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    if args.version {
        println!("rust-snell {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut cfg = if let Some(config_path) = &args.config {
        log::info!("configuration file specified, ignoring other flags");
        config::Config::parse_file_auto(config_path).unwrap_or_else(|e| {
            eprintln!("failed to load config file {}: {}", config_path, e);
            std::process::exit(1);
        })
    } else {
        let mut cfg = config::Config::default();
        cfg.server = args.server;
        cfg.listen = args.listen.clone();
        cfg.server_addr = args.server_addr.clone().unwrap_or_default();
        cfg.psk = args.psk.clone().unwrap_or_default();
        cfg.obfs = args.obfs.clone();
        cfg.obfs_host = args.obfs_host.clone();
        cfg.version = args.snell_version.clone();
        cfg
    };

    // Normalize obfs type
    if cfg.obfs == "none" || cfg.obfs == "off" {
        cfg.obfs = String::new();
    }

    if cfg.psk.is_empty() {
        eprintln!("error: PSK is required");
        std::process::exit(1);
    }

    if cfg.server {
        log::info!("rust-snell server, version: {}", env!("CARGO_PKG_VERSION"));
        if let Err(e) = snell::run_server(&cfg.listen, &cfg.psk, &cfg.obfs).await {
            eprintln!("server error: {}", e);
            std::process::exit(1);
        }
    } else {
        log::info!("rust-snell client, version: {}", env!("CARGO_PKG_VERSION"));
        if cfg.server_addr.is_empty() {
            eprintln!("error: server address is required for client mode");
            std::process::exit(1);
        }

        let is_v2 = cfg.version != "1";
        if cfg.obfs_host.is_empty() {
            log::info!("note: obfs host empty, using default bing.com");
            cfg.obfs_host = "www.bing.com".to_string();
        }

        let client =
            snell::SnellClient::new(&cfg.server_addr, &cfg.obfs, &cfg.obfs_host, &cfg.psk, is_v2);
        if let Err(e) = client.run(&cfg.listen).await {
            eprintln!("client error: {}", e);
            std::process::exit(1);
        }
    }
}

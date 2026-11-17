mod aead;
mod config;
mod obfs;
mod snell;
mod socks5;

use clap::Parser;

const DEFAULT_LISTEN: &str = "0.0.0.0:18888";
const DEFAULT_OBFS_HOST: &str = "bing.com";

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
    #[arg(short = 'l', default_value = DEFAULT_LISTEN)]
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
    #[arg(long, default_value = DEFAULT_OBFS_HOST)]
    obfs_host: String,

    /// Snell version (1 or 2, client only)
    #[arg(short = 'v', long = "snell-version", default_value = "2", value_parser = ["1", "2"])]
    snell_version: String,

    /// Show version
    #[arg(long)]
    version: bool,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    if args.version {
        println!("rust-snell {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut cfg = if let Some(config_path) = &args.config {
        log::info!("configuration file specified, ignoring other flags");
        config::Config::parse_file_auto(config_path).unwrap_or_else(|error| {
            eprintln!("failed to load config file {config_path}: {error}");
            std::process::exit(1);
        })
    } else {
        config::Config {
            server: args.server,
            listen: args.listen,
            server_addr: args.server_addr.unwrap_or_default(),
            psk: args.psk.unwrap_or_default(),
            obfs: args.obfs,
            obfs_host: args.obfs_host,
            version: args.snell_version,
        }
    };

    // Normalize obfs type
    if cfg.obfs == "none" || cfg.obfs == "off" {
        cfg.obfs.clear();
    }

    // 默认值同样适用于配置文件缺失字段的情况
    if cfg.listen.is_empty() {
        cfg.listen = DEFAULT_LISTEN.to_string();
    }
    if cfg.obfs_host.is_empty() {
        cfg.obfs_host = DEFAULT_OBFS_HOST.to_string();
    }

    if cfg.psk.is_empty() {
        eprintln!("error: PSK is required");
        std::process::exit(1);
    }

    if cfg.server {
        log::info!("rust-snell server, version: {}", env!("CARGO_PKG_VERSION"));
        if let Err(error) = snell::run_server(&cfg.listen, &cfg.psk, &cfg.obfs).await {
            eprintln!("server error: {error}");
            std::process::exit(1);
        }
    } else {
        log::info!("rust-snell client, version: {}", env!("CARGO_PKG_VERSION"));
        if cfg.server_addr.is_empty() {
            eprintln!("error: server address is required for client mode");
            std::process::exit(1);
        }

        let is_v2 = cfg.version != "1";
        let client =
            snell::SnellClient::new(&cfg.server_addr, &cfg.obfs, &cfg.obfs_host, &cfg.psk, is_v2);
        if let Err(error) = client.run(&cfg.listen).await {
            eprintln!("client error: {error}");
            std::process::exit(1);
        }
    }
}

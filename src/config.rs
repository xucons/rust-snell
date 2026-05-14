use std::fs;
use std::io;

#[derive(Debug, Default)]
pub struct Config {
    pub server: bool,
    pub listen: String,
    pub server_addr: String,
    pub psk: String,
    pub obfs: String,
    pub obfs_host: String,
    pub version: String,
}

impl Config {
    #[allow(dead_code)]
    pub fn parse_file(path: &str) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config = Config::default();

        let section = if config.server { "snell-server" } else { "snell-client" };
        let mut in_section = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                in_section = line[1..line.len()-1].trim() == section;
                continue;
            }
            if !in_section {
                // Try both sections to detect which one exists
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "listen" => config.listen = value.to_string(),
                    "server" => config.server_addr = value.to_string(),
                    "psk" => config.psk = value.to_string(),
                    "obfs" => config.obfs = value.to_string(),
                    "obfs-host" => config.obfs_host = value.to_string(),
                    "version" => config.version = value.to_string(),
                    _ => {}
                }
            }
        }

        Ok(config)
    }

    pub fn parse_file_auto(path: &str) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config = Config::default();

        let mut server_section = false;
        let mut client_section = false;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                let section = line[1..line.len()-1].trim();
                server_section = section == "snell-server";
                client_section = section == "snell-client";
                continue;
            }
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if server_section {
                    config.server = true;
                    match key {
                        "listen" => config.listen = value.to_string(),
                        "psk" => config.psk = value.to_string(),
                        "obfs" => config.obfs = value.to_string(),
                        _ => {}
                    }
                } else if client_section {
                    config.server = false;
                    match key {
                        "listen" => config.listen = value.to_string(),
                        "server" => config.server_addr = value.to_string(),
                        "psk" => config.psk = value.to_string(),
                        "obfs" => config.obfs = value.to_string(),
                        "obfs-host" => config.obfs_host = value.to_string(),
                        "version" => config.version = value.to_string(),
                        _ => {}
                    }
                }
            }
        }

        Ok(config)
    }
}

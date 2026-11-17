use std::fmt;
use std::fs;
use std::io;

#[derive(Default)]
pub struct Config {
    pub server: bool,
    pub listen: String,
    pub server_addr: String,
    pub psk: String,
    pub obfs: String,
    pub obfs_host: String,
    pub version: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("listen", &self.listen)
            .field("server_addr", &self.server_addr)
            .field("psk", &"***")
            .field("obfs", &self.obfs)
            .field("obfs_host", &self.obfs_host)
            .field("version", &self.version)
            .finish()
    }
}

impl Config {
    pub fn parse_file_auto(path: &str) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::parse_str(&content))
    }

    fn parse_str(content: &str) -> Self {
        let mut config = Config::default();

        let mut server_section = false;
        let mut client_section = false;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                let section = line[1..line.len() - 1].trim();
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

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_section() {
        let config =
            Config::parse_str("[snell-server]\nlisten = 0.0.0.0:12345\npsk = secret\nobfs = tls\n");
        assert!(config.server);
        assert_eq!(config.listen, "0.0.0.0:12345");
        assert_eq!(config.psk, "secret");
        assert_eq!(config.obfs, "tls");
    }

    #[test]
    fn parses_client_section() {
        let config = Config::parse_str(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = example.com:443\npsk = secret\nobfs = http\nobfs-host = www.bing.com\nversion = 1\n",
        );
        assert!(!config.server);
        assert_eq!(config.listen, "127.0.0.1:1080");
        assert_eq!(config.server_addr, "example.com:443");
        assert_eq!(config.obfs_host, "www.bing.com");
        assert_eq!(config.version, "1");
    }

    #[test]
    fn ignores_comments_and_unknown_keys() {
        let config = Config::parse_str(
            "# comment\n; another\n[snell-server]\nunknown = value\npsk = secret\n",
        );
        assert_eq!(config.psk, "secret");
        assert!(config.listen.is_empty());
    }

    #[test]
    fn debug_does_not_leak_psk() {
        let config = Config::parse_str("[snell-server]\npsk = super-secret\n");
        let text = format!("{config:?}");
        assert!(!text.contains("super-secret"));
        assert!(text.contains("***"));
    }
}

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use reticulum_core::identity::Identity;
use reticulum_node::rng::EntropySource;
use reticulum_tokio::OsEntropy;
use serde::Deserialize;
use zeroize::Zeroize;

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct IfacSettings {
    pub network_name: String,
    pub passphrase: String,
    #[serde(default)]
    pub size: Option<usize>,
}

impl core::fmt::Debug for IfacSettings {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IfacSettings")
            .field("network_name", &self.network_name)
            .field("passphrase", &"<redacted>")
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterfaceConfig {
    TcpClient {
        address: String,
        #[serde(default)]
        ifac: Option<IfacSettings>,
    },
    TcpServer {
        listen: String,
        #[serde(default)]
        ifac: Option<IfacSettings>,
    },
    Udp {
        listen: String,
        forward: String,
        #[serde(default)]
        ifac: Option<IfacSettings>,
    },
    Auto {
        interface: String,
        #[serde(default = "default_auto_group")]
        group_id: String,
        #[serde(default = "default_auto_discovery_port")]
        discovery_port: u16,
        #[serde(default = "default_auto_data_port")]
        data_port: u16,
        #[serde(default)]
        ifac: Option<IfacSettings>,
    },
    Serial {
        port: String,
        #[serde(default = "default_serial_baud")]
        baud: u32,
        #[serde(default)]
        ifac: Option<IfacSettings>,
    },
}

impl InterfaceConfig {
    pub fn ifac(&self) -> Option<&IfacSettings> {
        match self {
            Self::TcpClient { ifac, .. }
            | Self::TcpServer { ifac, .. }
            | Self::Udp { ifac, .. }
            | Self::Auto { ifac, .. }
            | Self::Serial { ifac, .. } => ifac.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "interface")]
    pub interfaces: Vec<InterfaceConfig>,
    pub tcp_addr: String,
    pub tcp_peers: Vec<String>,
    pub transport_enabled: bool,
    pub identity_path: PathBuf,
    pub app_name: String,
    pub aspects: Vec<String>,
    pub app_data: String,
    pub announce_interval_secs: u64,
    pub link_echo: bool,
    pub prove: bool,
    pub group_key_hex: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            tcp_addr: "127.0.0.1:4242".to_owned(),
            tcp_peers: Vec::new(),
            transport_enabled: false,
            identity_path: PathBuf::from("reticulum.identity"),
            app_name: "reticulum_rust".to_owned(),
            aspects: vec!["message".to_owned()],
            app_data: String::new(),
            announce_interval_secs: 30,
            link_echo: false,
            prove: false,
            group_key_hex: None,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> io::Result<Self> {
        let mut config = match path {
            Some(path) => {
                let text = fs::read_to_string(path)?;
                toml::from_str(&text)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            }
            None => Self::default(),
        };
        config.apply_environment();
        if config.aspects.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one destination aspect is required",
            ));
        }
        Ok(config)
    }

    fn apply_environment(&mut self) {
        if let Ok(value) = std::env::var("RETICULUM_TCP_ADDR") {
            self.tcp_addr = value;
        }
        if let Ok(value) = std::env::var("RETICULUM_TCP_PEERS") {
            self.tcp_peers = value
                .split(',')
                .map(str::trim)
                .filter(|peer| !peer.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Ok(value) = std::env::var("RETICULUM_TRANSPORT_ENABLED")
            && let Ok(enabled) = value.parse()
        {
            self.transport_enabled = enabled;
        }
        if let Ok(value) = std::env::var("RETICULUM_IDENTITY_PATH") {
            self.identity_path = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("RETICULUM_APP_NAME") {
            self.app_name = value;
        }
        if let Ok(value) = std::env::var("RETICULUM_ASPECTS") {
            self.aspects = value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Ok(value) = std::env::var("RETICULUM_APP_DATA") {
            self.app_data = value;
        }
        if let Ok(value) = std::env::var("RETICULUM_ANNOUNCE_INTERVAL_SECS")
            && let Ok(seconds) = value.parse()
        {
            self.announce_interval_secs = seconds;
        }
        if let Ok(value) = std::env::var("RETICULUM_LINK_ECHO")
            && let Ok(enabled) = value.parse()
        {
            self.link_echo = enabled;
        }
        if let Ok(value) = std::env::var("RETICULUM_PROVE")
            && let Ok(enabled) = value.parse()
        {
            self.prove = enabled;
        }
        if let Ok(value) = std::env::var("RETICULUM_GROUP_KEY") {
            self.group_key_hex = Some(value);
        }
    }

    pub fn peer_addresses(&self) -> Vec<&str> {
        if self.tcp_peers.is_empty() {
            vec![self.tcp_addr.as_str()]
        } else {
            self.tcp_peers.iter().map(String::as_str).collect()
        }
    }

    pub fn interface_configs(&self) -> Vec<InterfaceConfig> {
        if self.interfaces.is_empty() {
            self.peer_addresses()
                .into_iter()
                .map(|address| InterfaceConfig::TcpClient {
                    address: address.to_owned(),
                    ifac: None,
                })
                .collect()
        } else {
            self.interfaces.clone()
        }
    }

    pub fn group_key(&self) -> io::Result<Option<[u8; 64]>> {
        let Some(encoded) = self.group_key_hex.as_deref() else {
            return Ok(None);
        };
        let decoded = hex::decode(encoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let key = decoded.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "group key must be exactly 64 bytes",
            )
        })?;
        Ok(Some(key))
    }
}

fn default_auto_group() -> String {
    "reticulum".to_owned()
}

const fn default_auto_discovery_port() -> u16 {
    29_716
}

const fn default_auto_data_port() -> u16 {
    42_671
}

const fn default_serial_baud() -> u32 {
    9_600
}

pub fn save_or_create_identity(path: &Path) -> io::Result<Identity> {
    if path.exists() {
        return load_identity(path);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let mut private = [0u8; 64];
    OsEntropy.fill(&mut private);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return load_identity(path),
        Err(error) => return Err(error),
    };
    file.write_all(&private)?;
    file.sync_all()?;
    let identity = identity_from_private(&private);
    private.zeroize();
    identity
}

fn load_identity(path: &Path) -> io::Result<Identity> {
    let mut private = fs::read(path)?;
    let identity = identity_from_private(&private);
    private.zeroize();
    identity
}

fn identity_from_private(private: &[u8]) -> io::Result<Identity> {
    if private.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity file must contain exactly 64 bytes",
        ));
    }
    let x25519: [u8; 32] = private[..32]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid X25519 key"))?;
    let ed25519: [u8; 32] = private[32..]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Ed25519 key"))?;
    Ok(Identity::from_private_bytes(&x25519, &ed25519))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persist_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        let identity = save_or_create_identity(&path).unwrap();
        let reloaded = save_or_create_identity(&path).unwrap();
        assert_eq!(identity.hash(), reloaded.hash());
    }

    #[test]
    fn parses_toml_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reticulum.toml");
        std::fs::write(
            &path,
            r#"
tcp_addr = "localhost:5252"
tcp_peers = ["localhost:5253", "localhost:5254"]
transport_enabled = true
identity_path = "test.identity"
app_name = "chat"
aspects = ["v1", "messages"]
app_data = "hello"
"#,
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        assert_eq!(config.tcp_addr, "localhost:5252");
        assert_eq!(
            config.peer_addresses(),
            ["localhost:5253", "localhost:5254"]
        );
        assert!(config.transport_enabled);
        assert_eq!(config.aspects, ["v1", "messages"]);
    }

    #[test]
    fn parses_all_typed_interfaces_and_ifac() {
        let config: Config = toml::from_str(
            r#"
[[interface]]
type = "tcp_client"
address = "127.0.0.1:4242"
ifac = { network_name = "mesh", passphrase = "secret", size = 8 }

[[interface]]
type = "tcp_server"
listen = "[::1]:4243"

[[interface]]
type = "udp"
listen = "127.0.0.1:4244"
forward = "127.0.0.1:4245"

[[interface]]
type = "auto"
interface = "en0"

[[interface]]
type = "serial"
port = "/dev/ttyUSB0"
"#,
        )
        .unwrap();
        assert_eq!(config.interfaces.len(), 5);
        assert!(matches!(
            &config.interfaces[0],
            InterfaceConfig::TcpClient {
                address,
                ifac: Some(IfacSettings { size: Some(8), .. }),
            } if address == "127.0.0.1:4242"
        ));
        assert!(matches!(
            &config.interfaces[3],
            InterfaceConfig::Auto {
                group_id,
                discovery_port: 29_716,
                data_port: 42_671,
                ..
            } if group_id == "reticulum"
        ));
        assert!(matches!(
            &config.interfaces[4],
            InterfaceConfig::Serial { baud: 9_600, .. }
        ));
    }

    #[test]
    fn legacy_tcp_fields_remain_compatible() {
        let config: Config =
            toml::from_str(r#"tcp_peers = ["127.0.0.1:5001", "127.0.0.1:5002"]"#).unwrap();
        assert_eq!(
            config.interface_configs(),
            [
                InterfaceConfig::TcpClient {
                    address: "127.0.0.1:5001".to_owned(),
                    ifac: None,
                },
                InterfaceConfig::TcpClient {
                    address: "127.0.0.1:5002".to_owned(),
                    ifac: None,
                }
            ]
        );
    }
}

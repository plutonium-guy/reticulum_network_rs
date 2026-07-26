use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use reticulum_core::identity::Identity;
use reticulum_node::rng::EntropySource;
use reticulum_tokio::OsEntropy;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub tcp_addr: String,
    pub identity_path: PathBuf,
    pub app_name: String,
    pub aspects: Vec<String>,
    pub app_data: String,
    pub announce_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_addr: "127.0.0.1:4242".to_owned(),
            identity_path: PathBuf::from("reticulum.identity"),
            app_name: "reticulum_rust".to_owned(),
            aspects: vec!["message".to_owned()],
            app_data: String::new(),
            announce_interval_secs: 30,
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
    }
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
    identity_from_private(&private)
}

fn load_identity(path: &Path) -> io::Result<Identity> {
    let private = fs::read(path)?;
    identity_from_private(&private)
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
identity_path = "test.identity"
app_name = "chat"
aspects = ["v1", "messages"]
app_data = "hello"
"#,
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        assert_eq!(config.tcp_addr, "localhost:5252");
        assert_eq!(config.aspects, ["v1", "messages"]);
    }
}

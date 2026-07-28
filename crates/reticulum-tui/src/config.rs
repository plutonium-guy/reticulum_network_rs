use std::{
    io,
    path::{Path, PathBuf},
};

use reticulum_cli::config::{Config, InterfaceConfig};

const DEFAULT_GROUP: &str = "reticulum";
const DEFAULT_DISCOVERY_PORT: u16 = 29_716;
const DEFAULT_DATA_PORT: u16 = 42_671;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub config_path: Option<PathBuf>,
    pub identity_path: Option<PathBuf>,
}

/// Returns the zero-config, infrastructure-free TUI configuration.
pub fn default_config() -> Config {
    Config {
        interfaces: vec![InterfaceConfig::Auto {
            // The shared builder selects the first IPv6 link-local device when
            // this is empty. An explicit config can pin a device by name.
            interface: String::new(),
            group_id: DEFAULT_GROUP.to_owned(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            ifac: None,
        }],
        identity_path: PathBuf::from("reticulum-tui.identity"),
        app_name: "reticulum_tui".to_owned(),
        aspects: vec!["chat".to_owned()],
        ..Config::default()
    }
}

pub fn load_config(path: Option<&Path>) -> io::Result<Config> {
    match path {
        Some(path) => Config::load(Some(path)),
        None => Ok(default_config()),
    }
}

pub fn parse_args<I>(arguments: I) -> io::Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut config_path = None;
    let mut identity_path = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let slot = match argument.as_str() {
            "--config" => &mut config_path,
            "--identity" => &mut identity_path,
            "-h" | "--help" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: reticulum-tui [--config PATH] [--identity PATH]",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                ));
            }
        };
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{argument} requires a path"),
            )
        })?;
        *slot = Some(PathBuf::from(value));
    }
    Ok(Options {
        config_path,
        identity_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_exactly_one_auto_interface() {
        let config = default_config();

        assert_eq!(config.interfaces.len(), 1);
        assert!(matches!(config.interfaces[0], InterfaceConfig::Auto { .. }));
    }

    #[test]
    fn parses_config_and_identity_paths() {
        let options = parse_args([
            "--config".to_owned(),
            "mesh.toml".to_owned(),
            "--identity".to_owned(),
            "peer.identity".to_owned(),
        ])
        .unwrap();

        assert_eq!(options.config_path, Some(PathBuf::from("mesh.toml")));
        assert_eq!(options.identity_path, Some(PathBuf::from("peer.identity")));
    }
}

//! Shared configuration and interface construction for native Reticulum clients.

pub mod config;

use std::io;

use config::{Config, IfacSettings, InterfaceConfig};
use reticulum_tokio::interface::{AsyncInterface, IfacConfig, with_ifac};
use reticulum_tokio::{tcp::TcpClientInterface, udp::UdpInterface};

/// Builds every outbound or peer-to-peer interface configured for a node.
///
/// TCP server entries are intentionally skipped: listeners require the dynamic
/// registrar owned by the daemon and are not part of the decentralized client
/// startup path.
pub async fn build_interfaces(config: &Config) -> io::Result<Vec<Box<dyn AsyncInterface>>> {
    let mut interfaces: Vec<Box<dyn AsyncInterface>> = Vec::new();
    for configured in config.interface_configs() {
        let ifac = build_ifac(configured.ifac())?;
        let interface: Box<dyn AsyncInterface> = match configured {
            InterfaceConfig::TcpClient { address, .. } => {
                let interface = TcpClientInterface::connect(&address)
                    .await?
                    .with_id(next_interface_id(interfaces.len())?);
                Box::new(interface)
            }
            InterfaceConfig::TcpServer { .. } => continue,
            InterfaceConfig::Udp {
                listen, forward, ..
            } => {
                let interface = UdpInterface::bind(&listen, &forward)
                    .await?
                    .with_id(next_interface_id(interfaces.len())?);
                Box::new(interface)
            }
            InterfaceConfig::Auto {
                interface,
                group_id,
                discovery_port,
                data_port,
                ..
            } => {
                let interface = reticulum_tokio::auto::AutoInterface::new_with_ports(
                    &group_id,
                    discovery_port,
                    data_port,
                    &interface,
                )
                .await?
                .with_id(next_interface_id(interfaces.len())?);
                Box::new(interface)
            }
            InterfaceConfig::Serial { port, baud, .. } => {
                #[cfg(feature = "serial")]
                {
                    let interface = reticulum_tokio::serial::SerialInterface::open(&port, baud)?
                        .with_id(next_interface_id(interfaces.len())?);
                    Box::new(interface)
                }
                #[cfg(not(feature = "serial"))]
                {
                    let _ = (port, baud, ifac);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "serial interface requires reticulum-cli feature \"serial\"",
                    ));
                }
            }
        };
        interfaces.push(wrap_ifac(interface, ifac));
    }
    Ok(interfaces)
}

/// Converts user-facing IFAC settings into the Tokio interface configuration.
pub fn build_ifac(settings: Option<&IfacSettings>) -> io::Result<Option<IfacConfig>> {
    settings
        .map(|settings| {
            if settings.network_name.is_empty() && settings.passphrase.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IFAC requires a network name, a passphrase, or both",
                ));
            }
            let config = IfacConfig::new(&settings.network_name, &settings.passphrase);
            match settings.size {
                Some(size) => config.with_size(size),
                None => Ok(config),
            }
        })
        .transpose()
}

fn next_interface_id(index: usize) -> io::Result<u16> {
    u16::try_from(index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many interfaces"))
}

fn wrap_ifac(
    interface: Box<dyn AsyncInterface>,
    ifac: Option<IfacConfig>,
) -> Box<dyn AsyncInterface> {
    match ifac {
        Some(ifac) => with_ifac(interface, ifac),
        None => interface,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;

    #[tokio::test]
    async fn builds_configured_auto_interface() {
        let Some(interface) = if_addrs::get_if_addrs()
            .expect("interfaces")
            .into_iter()
            .find(|candidate| {
                matches!(
                    candidate.ip(),
                    IpAddr::V6(ip) if ip.is_unicast_link_local()
                )
            })
            .map(|candidate| candidate.name)
        else {
            // Some CI containers have no IPv6 link-local device.
            return;
        };
        let config = Config {
            interfaces: vec![InterfaceConfig::Auto {
                interface,
                group_id: "reticulum-cli-test".to_owned(),
                discovery_port: 0,
                data_port: 0,
                ifac: None,
            }],
            ..Config::default()
        };

        let interfaces = build_interfaces(&config)
            .await
            .expect("build AutoInterface");

        assert_eq!(interfaces.len(), 1);
    }

    #[test]
    fn ipv6_link_local_predicate_is_strict() {
        assert!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_unicast_link_local());
        assert!(!Ipv6Addr::LOCALHOST.is_unicast_link_local());
    }
}

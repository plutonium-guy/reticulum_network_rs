use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use async_trait::async_trait;
use reticulum_core::hash::full_hash;
use reticulum_interface::{Framing, Interface};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, time::Interval};

pub const AUTO_HW_MTU: usize = 1_196;
pub const DEFAULT_DISCOVERY_PORT: u16 = 29_716;
pub const DEFAULT_DATA_PORT: u16 = 42_671;
const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1_600);

/// RNS-compatible IPv6 link-local peer discovery and packet exchange.
pub struct AutoInterface {
    id: u16,
    group_id: Vec<u8>,
    local_ip: Ipv6Addr,
    interface_index: u32,
    multicast_addr: Ipv6Addr,
    discovery_port: u16,
    data_port: u16,
    discovery: UdpSocket,
    reverse_discovery: UdpSocket,
    data: UdpSocket,
    peers: BTreeMap<Ipv6Addr, SocketAddrV6>,
    announce: Interval,
}

impl AutoInterface {
    pub async fn new(group_id: &str, discovery_port: u16, iface_name: &str) -> io::Result<Self> {
        Self::new_with_ports(group_id, discovery_port, DEFAULT_DATA_PORT, iface_name).await
    }

    pub async fn new_with_ports(
        group_id: &str,
        discovery_port: u16,
        data_port: u16,
        iface_name: &str,
    ) -> io::Result<Self> {
        let reverse_discovery_port = discovery_port.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "AutoInterface discovery port must be below 65535",
            )
        })?;
        let (local_ip, interface_index) = link_local_interface(iface_name)?;
        let multicast_addr = multicast_address(group_id.as_bytes());
        let discovery = multicast_socket(multicast_addr, discovery_port, interface_index)?;
        let reverse_discovery = UdpSocket::bind(SocketAddrV6::new(
            local_ip,
            reverse_discovery_port,
            0,
            interface_index,
        ))
        .await?;
        let data =
            UdpSocket::bind(SocketAddrV6::new(local_ip, data_port, 0, interface_index)).await?;
        let mut announce = tokio::time::interval(ANNOUNCE_INTERVAL);
        announce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Ok(Self {
            id: 0,
            group_id: group_id.as_bytes().to_vec(),
            local_ip,
            interface_index,
            multicast_addr,
            discovery_port,
            data_port,
            discovery,
            reverse_discovery,
            data,
            peers: BTreeMap::new(),
            announce,
        })
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    async fn announce(&self) -> io::Result<()> {
        let destination = SocketAddrV6::new(
            self.multicast_addr,
            self.discovery_port,
            0,
            self.interface_index,
        );
        self.discovery
            .send_to(&discovery_token(&self.group_id, self.local_ip), destination)
            .await?;
        Ok(())
    }

    async fn process_discovery(
        &mut self,
        payload: &[u8],
        source: SocketAddr,
        reverse: bool,
    ) -> io::Result<()> {
        let SocketAddr::V6(source) = source else {
            return Ok(());
        };
        if *source.ip() == self.local_ip || payload != discovery_token(&self.group_id, *source.ip())
        {
            return Ok(());
        }

        self.peers.insert(
            *source.ip(),
            SocketAddrV6::new(*source.ip(), self.data_port, 0, self.interface_index),
        );
        if reverse {
            let destination = SocketAddrV6::new(
                *source.ip(),
                self.discovery_port + 1,
                0,
                self.interface_index,
            );
            self.discovery
                .send_to(&discovery_token(&self.group_id, self.local_ip), destination)
                .await?;
        }
        Ok(())
    }
}

impl Interface for AutoInterface {
    const FRAMING: Framing = Framing::Raw;
    const HW_MTU: usize = AUTO_HW_MTU;
}

#[async_trait]
impl crate::interface::AsyncInterface for AutoInterface {
    fn id(&self) -> u16 {
        self.id
    }

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut discovery_buffer = [0u8; 1_024];
        let mut reverse_buffer = [0u8; 1_024];
        let mut packet_buffer = [0u8; AUTO_HW_MTU + 1];
        loop {
            tokio::select! {
                _ = self.announce.tick() => self.announce().await?,
                received = self.discovery.recv_from(&mut discovery_buffer) => {
                    let (read, source) = received?;
                    self.process_discovery(&discovery_buffer[..read], source, true).await?;
                }
                received = self.reverse_discovery.recv_from(&mut reverse_buffer) => {
                    let (read, source) = received?;
                    self.process_discovery(&reverse_buffer[..read], source, false).await?;
                }
                received = self.data.recv_from(&mut packet_buffer) => {
                    let (read, source) = received?;
                    let SocketAddr::V6(source) = source else {
                        continue;
                    };
                    if read <= AUTO_HW_MTU && self.peers.contains_key(source.ip()) {
                        return Ok(Some(packet_buffer[..read].to_vec()));
                    }
                }
            }
        }
    }

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
        if raw.len() > AUTO_HW_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AutoInterface packet exceeds RNS hardware MTU",
            ));
        }
        for peer in self.peers.values() {
            self.data.send_to(raw, peer).await?;
        }
        Ok(())
    }
}

fn link_local_interface(iface_name: &str) -> io::Result<(Ipv6Addr, u32)> {
    if_addrs::get_if_addrs()?
        .into_iter()
        .find_map(|interface| {
            if interface.name == iface_name {
                match (interface.ip(), interface.index) {
                    (IpAddr::V6(ip), Some(index)) if ip.is_unicast_link_local() => {
                        Some((ip, index))
                    }
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("interface {iface_name} has no IPv6 link-local address"),
            )
        })
}

fn multicast_address(group_id: &[u8]) -> Ipv6Addr {
    let hash = full_hash(group_id);
    Ipv6Addr::new(
        0xff12,
        0,
        u16::from_be_bytes([hash[2], hash[3]]),
        u16::from_be_bytes([hash[4], hash[5]]),
        u16::from_be_bytes([hash[6], hash[7]]),
        u16::from_be_bytes([hash[8], hash[9]]),
        u16::from_be_bytes([hash[10], hash[11]]),
        u16::from_be_bytes([hash[12], hash[13]]),
    )
}

fn discovery_token(group_id: &[u8], source: Ipv6Addr) -> [u8; 32] {
    let mut material = Vec::with_capacity(group_id.len() + 39);
    material.extend_from_slice(group_id);
    material.extend_from_slice(source.to_string().as_bytes());
    full_hash(&material)
}

fn multicast_socket(
    multicast_addr: Ipv6Addr,
    port: u16,
    interface_index: u32,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_multicast_if_v6(interface_index)?;
    socket.join_multicast_v6(&multicast_addr, interface_index)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_rns_multicast_address_and_authenticated_token() {
        assert_eq!(
            multicast_address(b"reticulum"),
            "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            hex::encode(discovery_token(b"reticulum", "fe80::1".parse().unwrap())),
            "97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163"
        );
    }

    #[test]
    fn resolves_an_available_link_local_interface() {
        let Some(name) = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|interface| {
                matches!(
                    interface.ip(),
                    IpAddr::V6(ip) if ip.is_unicast_link_local()
                )
            })
            .map(|interface| interface.name)
        else {
            return;
        };

        assert!(link_local_interface(&name).is_ok());
    }
}

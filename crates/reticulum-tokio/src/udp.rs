use std::{
    io,
    net::{SocketAddr, ToSocketAddrs as _},
};

use async_trait::async_trait;
use reticulum_interface::{Framing, Interface};
use tokio::net::UdpSocket;

pub const UDP_HW_MTU: usize = 1_064;

/// Raw Reticulum packets carried one-per-datagram, matching RNS UDPInterface.
pub struct UdpInterface {
    id: u16,
    socket: UdpSocket,
    peer: SocketAddr,
}

impl UdpInterface {
    pub async fn bind(listen_addr: &str, peer_addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        socket.set_broadcast(true)?;
        let peer = peer_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP peer"))?;
        Ok(Self {
            id: 0,
            socket,
            peer,
        })
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl Interface for UdpInterface {
    const FRAMING: Framing = Framing::Raw;
    const HW_MTU: usize = UDP_HW_MTU;
}

#[async_trait]
impl crate::interface::AsyncInterface for UdpInterface {
    fn id(&self) -> u16 {
        self.id
    }

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buffer = [0u8; UDP_HW_MTU + 1];
        loop {
            let (read, _) = self.socket.recv_from(&mut buffer).await?;
            if read <= UDP_HW_MTU {
                return Ok(Some(buffer[..read].to_vec()));
            }
        }
    }

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
        if raw.len() > UDP_HW_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP packet exceeds RNS hardware MTU",
            ));
        }
        let sent = self.socket.send_to(raw, self.peer).await?;
        if sent == raw.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram write",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::AsyncInterface;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn exchanges_raw_datagrams_and_drops_oversize() {
        let probe_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = probe_a.local_addr().unwrap();
        drop(probe_a);
        let probe_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = probe_b.local_addr().unwrap();
        drop(probe_b);

        let mut a = UdpInterface::bind(&addr_a.to_string(), &addr_b.to_string())
            .await
            .unwrap();
        let mut b = UdpInterface::bind(&addr_b.to_string(), &addr_a.to_string())
            .await
            .unwrap();

        a.send_packet(b"one datagram").await.unwrap();
        assert_eq!(b.recv_packet().await.unwrap().unwrap(), b"one datagram");
        b.send_packet(b"reply").await.unwrap();
        assert_eq!(a.recv_packet().await.unwrap().unwrap(), b"reply");

        let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        raw.send_to(&vec![0xAA; UDP_HW_MTU + 1], addr_b)
            .await
            .unwrap();
        a.send_packet(b"after oversize").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), b.recv_packet())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            b"after oversize"
        );
        assert_eq!(
            a.send_packet(&vec![0; UDP_HW_MTU + 1])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

use std::collections::BTreeMap;

use reticulum_node::{Event, NodeError, clock::Clock, node::Node};
use tokio::sync::mpsc;

use crate::{OsEntropy, tcp::TcpClientInterface};

const INTERFACE_ID: u16 = 0;
const COMMAND_CAPACITY: usize = 32;
const INTERFACE_CAPACITY: usize = 32;

enum Command {
    AnnounceAll(Vec<u8>),
    Send {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverClosed;

#[derive(Clone)]
pub struct DriverHandle {
    commands: mpsc::Sender<Command>,
}

impl DriverHandle {
    pub async fn announce_all(&self, app_data: &[u8]) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::AnnounceAll(app_data.to_vec()))
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn send(&self, dest_hash: [u8; 16], plaintext: &[u8]) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::Send {
                dest_hash,
                plaintext: plaintext.to_vec(),
            })
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn shutdown(&self) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::Shutdown)
            .await
            .map_err(|_| DriverClosed)
    }
}

enum Inbound {
    Packet {
        interface: u16,
        bytes: Vec<u8>,
    },
    Closed {
        interface: u16,
    },
    Error {
        interface: u16,
        error: std::io::Error,
    },
}

pub struct Driver<C: Clock> {
    node: Node<C>,
    interfaces: BTreeMap<u16, mpsc::Sender<Vec<u8>>>,
    inbound: mpsc::Receiver<Inbound>,
    entropy: OsEntropy,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
}

impl<C: Clock + Send + 'static> Driver<C> {
    pub fn new(
        node: Node<C>,
        interface: TcpClientInterface,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle) {
        Self::new_multi(node, vec![(INTERFACE_ID, interface)], events)
    }

    pub fn new_multi(
        mut node: Node<C>,
        interfaces: Vec<(u16, TcpClientInterface)>,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle) {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(INTERFACE_CAPACITY);
        let mut interface_senders = BTreeMap::new();
        for (id, interface) in interfaces {
            node.register_interface(id);
            let (outbound_tx, outbound_rx) = mpsc::channel(INTERFACE_CAPACITY);
            interface_senders.insert(id, outbound_tx);
            tokio::spawn(run_interface(
                id,
                interface,
                outbound_rx,
                inbound_tx.clone(),
            ));
        }
        (
            Self {
                node,
                interfaces: interface_senders,
                inbound: inbound_rx,
                entropy: OsEntropy,
                commands: commands_rx,
                events,
            },
            DriverHandle {
                commands: commands_tx,
            },
        )
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        loop {
            tokio::select! {
                command = self.commands.recv() => {
                    match command {
                        Some(Command::AnnounceAll(app_data)) => {
                            let destinations: Vec<_> = self.node.local_destinations().collect();
                            let interfaces: Vec<_> = self.interfaces.keys().copied().collect();
                            for interface in interfaces {
                                for dest_hash in &destinations {
                                    self.node.send_announce(
                                        dest_hash,
                                        &app_data,
                                        &mut self.entropy,
                                        interface,
                                    );
                                }
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::Send { dest_hash, plaintext }) => {
                            if let Err(error) =
                                self.node.send_message(&dest_hash, &plaintext, &mut self.entropy)
                            {
                                self.emit(Event::Error(error)).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::Shutdown) | None => return Ok(()),
                    }
                }
                inbound = self.inbound.recv() => {
                    match inbound {
                        Some(Inbound::Packet { interface, bytes }) => {
                            for event in self.node.handle_inbound(&bytes, interface) {
                                self.emit(event).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Inbound::Closed { interface }) => {
                            self.interfaces.remove(&interface);
                            if self.interfaces.is_empty() {
                                return Ok(());
                            }
                        }
                        Some(Inbound::Error { interface, error }) => {
                            self.interfaces.remove(&interface);
                            if self.interfaces.is_empty() {
                                return Err(error);
                            }
                            self.emit(Event::Error(NodeError::Unknown)).await;
                        }
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn drain_outbound(&mut self) -> std::io::Result<()> {
        while let Some((interface, packet)) = self.node.poll_outbound() {
            let Some(sender) = self.interfaces.get(&interface).cloned() else {
                self.emit(Event::Error(NodeError::Unknown)).await;
                continue;
            };
            if sender.send(packet).await.is_err() {
                self.interfaces.remove(&interface);
                self.emit(Event::Error(NodeError::Unknown)).await;
            }
        }
        Ok(())
    }

    async fn emit(&self, event: Event) {
        let _ = self.events.send(event).await;
    }
}

async fn run_interface(
    id: u16,
    mut interface: TcpClientInterface,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Inbound>,
) {
    loop {
        tokio::select! {
            packet = outbound.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                if let Err(error) = interface.send_packet(&packet).await {
                    let _ = inbound.send(Inbound::Error { interface: id, error }).await;
                    return;
                }
            }
            packet = interface.recv_packet() => {
                match packet {
                    Ok(Some(bytes)) => {
                        if inbound.send(Inbound::Packet { interface: id, bytes }).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = inbound.send(Inbound::Closed { interface: id }).await;
                        return;
                    }
                    Err(error) => {
                        let _ = inbound.send(Inbound::Error { interface: id, error }).await;
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::identity::Identity;
    use reticulum_node::{Event, node::Node};
    use tokio::{
        net::TcpListener,
        sync::mpsc,
        time::{Duration, timeout},
    };

    #[tokio::test]
    async fn drivers_exchange_announce_and_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_interface = connect.await.unwrap().unwrap();
        let server_interface = TcpClientInterface::from_stream(server_stream);

        let mut a_node = Node::new(Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]));
        let a_dest = a_node.register_single_destination("chat", &["a"]);
        let mut b_node = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
        let b_dest = b_node.register_single_destination("chat", &["b"]);

        let (a_events_tx, mut a_events_rx) = mpsc::channel(16);
        let (b_events_tx, mut b_events_rx) = mpsc::channel(16);
        let (a_driver, a_handle) = Driver::new(a_node, client_interface, a_events_tx);
        let (b_driver, b_handle) = Driver::new(b_node, server_interface, b_events_tx);
        let a_task = tokio::spawn(a_driver.run());
        let b_task = tokio::spawn(b_driver.run());

        a_handle.announce_all(b"").await.unwrap();
        b_handle.announce_all(b"").await.unwrap();

        let a_event = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(a_event, Event::Announce { dest_hash, .. } if dest_hash == b_dest));
        let b_event = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(b_event, Event::Announce { dest_hash, .. } if dest_hash == a_dest));

        a_handle.send(b_dest, b"over tcp").await.unwrap();
        let message = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(message, Event::Message { plaintext, .. } if plaintext == b"over tcp"));

        a_handle.shutdown().await.unwrap();
        b_handle.shutdown().await.unwrap();
        a_task.await.unwrap().unwrap();
        b_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn three_drivers_route_message_across_transport_line() {
        async fn tcp_pair() -> (TcpClientInterface, TcpClientInterface) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
            let (server_stream, _) = listener.accept().await.unwrap();
            (
                connect.await.unwrap().unwrap(),
                TcpClientInterface::from_stream(server_stream),
            )
        }

        let (a_interface, relay_a_interface) = tcp_pair().await;
        let (relay_c_interface, c_interface) = tcp_pair().await;

        let mut a_node = Node::new(Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]));
        a_node.register_single_destination("chat", &["a"]);
        let mut relay_node = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
        relay_node.enable_transport();
        let mut c_node = Node::new(Identity::from_private_bytes(&[5u8; 32], &[6u8; 32]));
        let c_dest = c_node.register_single_destination("chat", &["c"]);

        let (a_events_tx, mut a_events_rx) = mpsc::channel(16);
        let (relay_events_tx, _relay_events_rx) = mpsc::channel(16);
        let (c_events_tx, mut c_events_rx) = mpsc::channel(16);
        let (a_driver, a_handle) = Driver::new(a_node, a_interface, a_events_tx);
        let (relay_driver, relay_handle) = Driver::new_multi(
            relay_node,
            vec![(10, relay_a_interface), (20, relay_c_interface)],
            relay_events_tx,
        );
        let (c_driver, c_handle) = Driver::new(c_node, c_interface, c_events_tx);
        let a_task = tokio::spawn(a_driver.run());
        let relay_task = tokio::spawn(relay_driver.run());
        let c_task = tokio::spawn(c_driver.run());

        c_handle.announce_all(b"").await.unwrap();
        let learned = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(learned, Event::Announce { dest_hash, hops: 2 } if dest_hash == c_dest));

        a_handle.send(c_dest, b"across transport").await.unwrap();
        let delivered = timeout(Duration::from_secs(2), c_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            delivered,
            Event::Message { plaintext, .. } if plaintext == b"across transport"
        ));

        a_handle.shutdown().await.unwrap();
        relay_handle.shutdown().await.unwrap();
        c_handle.shutdown().await.unwrap();
        a_task.await.unwrap().unwrap();
        relay_task.await.unwrap().unwrap();
        c_task.await.unwrap().unwrap();
    }
}

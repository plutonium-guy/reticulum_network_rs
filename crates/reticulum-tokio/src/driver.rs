use std::{
    collections::BTreeMap,
    future::pending,
    io,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use reticulum_node::{Event, NodeError, clock::Clock, node::Node};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Duration, MissedTickBehavior},
};

use crate::{OsEntropy, interface::AsyncInterface, tcp::TcpClientInterface};

const INTERFACE_ID: u16 = 0;
const COMMAND_CAPACITY: usize = 32;
const INTERFACE_CAPACITY: usize = 32;
const REGISTRATION_CAPACITY: usize = 16;

enum Command {
    AnnounceAll(Vec<u8>),
    Send {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    SendWithReceipt {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
        reply: oneshot::Sender<Result<[u8; 32], NodeError>>,
    },
    SendGroup {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    SendPlain {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    EstablishLink {
        dest_hash: [u8; 16],
        reply: oneshot::Sender<Result<[u8; 16], NodeError>>,
    },
    LinkSend {
        link_id: [u8; 16],
        plaintext: Vec<u8>,
    },
    SendResource {
        link_id: [u8; 16],
        data: Vec<u8>,
        reply: oneshot::Sender<Result<[u8; 32], NodeError>>,
    },
    CloseLink([u8; 16]),
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverClosed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Closed,
    Node(NodeError),
}

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

    pub async fn send_with_receipt(
        &self,
        dest_hash: [u8; 16],
        plaintext: &[u8],
    ) -> Result<[u8; 32], DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::SendWithReceipt {
                dest_hash,
                plaintext: plaintext.to_vec(),
                reply,
            })
            .await
            .map_err(|_| DriverError::Closed)?;
        response
            .await
            .map_err(|_| DriverError::Closed)?
            .map_err(DriverError::Node)
    }

    pub async fn send_group(
        &self,
        dest_hash: [u8; 16],
        plaintext: &[u8],
    ) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::SendGroup {
                dest_hash,
                plaintext: plaintext.to_vec(),
            })
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn send_plain(
        &self,
        dest_hash: [u8; 16],
        plaintext: &[u8],
    ) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::SendPlain {
                dest_hash,
                plaintext: plaintext.to_vec(),
            })
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn establish_link(&self, dest_hash: [u8; 16]) -> Result<[u8; 16], DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::EstablishLink { dest_hash, reply })
            .await
            .map_err(|_| DriverError::Closed)?;
        response
            .await
            .map_err(|_| DriverError::Closed)?
            .map_err(DriverError::Node)
    }

    pub async fn link_send(&self, link_id: [u8; 16], plaintext: &[u8]) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::LinkSend {
                link_id,
                plaintext: plaintext.to_vec(),
            })
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn close_link(&self, link_id: [u8; 16]) -> Result<(), DriverClosed> {
        self.commands
            .send(Command::CloseLink(link_id))
            .await
            .map_err(|_| DriverClosed)
    }

    pub async fn send_resource(
        &self,
        link_id: [u8; 16],
        data: &[u8],
    ) -> Result<[u8; 32], DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::SendResource {
                link_id,
                data: data.to_vec(),
                reply,
            })
            .await
            .map_err(|_| DriverError::Closed)?;
        response
            .await
            .map_err(|_| DriverError::Closed)?
            .map_err(DriverError::Node)
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
    inbound_sender: mpsc::Sender<Inbound>,
    inbound: mpsc::Receiver<Inbound>,
    registrations: Option<mpsc::Receiver<Box<dyn AsyncInterface>>>,
    keep_alive: bool,
    announce_data: Option<Vec<u8>>,
    entropy: OsEntropy,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
}

/// Registration handle for interfaces created after the driver starts, such
/// as accepted TCP connections and discovered peers.
#[derive(Clone)]
pub struct InterfaceRegistrar {
    registrations: mpsc::Sender<Box<dyn AsyncInterface>>,
    next_id: Arc<AtomicU32>,
}

impl InterfaceRegistrar {
    pub fn allocate_id(&self) -> io::Result<u16> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        u16::try_from(id).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface id space exhausted")
        })
    }

    pub async fn register(&self, interface: Box<dyn AsyncInterface>) -> io::Result<()> {
        self.registrations
            .send(interface)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver stopped"))
    }
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
        node: Node<C>,
        interfaces: Vec<(u16, TcpClientInterface)>,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle) {
        let interfaces = interfaces
            .into_iter()
            .map(|(id, interface)| Box::new(interface.with_id(id)) as Box<dyn AsyncInterface>)
            .collect();
        Self::new_interfaces(node, interfaces, events)
    }

    pub fn new_interfaces(
        node: Node<C>,
        interfaces: Vec<Box<dyn AsyncInterface>>,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle) {
        let (driver, handle, _) = Self::build(node, interfaces, events, false);
        (driver, handle)
    }

    pub fn new_dynamic(
        node: Node<C>,
        interfaces: Vec<Box<dyn AsyncInterface>>,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle, InterfaceRegistrar) {
        Self::build(node, interfaces, events, true)
    }

    fn build(
        mut node: Node<C>,
        interfaces: Vec<Box<dyn AsyncInterface>>,
        events: mpsc::Sender<Event>,
        keep_alive: bool,
    ) -> (Self, DriverHandle, InterfaceRegistrar) {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(INTERFACE_CAPACITY);
        let (registrations_tx, registrations_rx) = mpsc::channel(REGISTRATION_CAPACITY);
        let mut interface_senders = BTreeMap::new();
        let mut highest_id = None;
        for interface in interfaces {
            let id = interface.id();
            highest_id = Some(highest_id.map_or(id, |highest: u16| highest.max(id)));
            node.register_interface(id);
            interface_senders.insert(id, spawn_interface(interface, inbound_tx.clone()));
        }
        let registrar = InterfaceRegistrar {
            registrations: registrations_tx,
            next_id: Arc::new(AtomicU32::new(highest_id.map_or(0, |id| u32::from(id) + 1))),
        };
        (
            Self {
                node,
                interfaces: interface_senders,
                inbound_sender: inbound_tx,
                inbound: inbound_rx,
                registrations: Some(registrations_rx),
                keep_alive,
                announce_data: None,
                entropy: OsEntropy,
                commands: commands_rx,
                events,
            },
            DriverHandle {
                commands: commands_tx,
            },
            registrar,
        )
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tokio::select! {
                command = self.commands.recv() => {
                    match command {
                        Some(Command::AnnounceAll(app_data)) => {
                            self.announce_data = Some(app_data.clone());
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
                        Some(Command::SendWithReceipt {
                            dest_hash,
                            plaintext,
                            reply,
                        }) => {
                            let result = self.node.send_message_with_receipt(
                                &dest_hash,
                                &plaintext,
                                &mut self.entropy,
                            );
                            let _ = reply.send(result);
                            self.drain_outbound().await?;
                        }
                        Some(Command::SendGroup { dest_hash, plaintext }) => {
                            if let Err(error) = self.node.send_group_message(
                                &dest_hash,
                                &plaintext,
                                &mut self.entropy,
                            ) {
                                self.emit(Event::Error(error)).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::SendPlain { dest_hash, plaintext }) => {
                            if let Err(error) =
                                self.node.send_plain_message(&dest_hash, &plaintext)
                            {
                                self.emit(Event::Error(error)).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::EstablishLink { dest_hash, reply }) => {
                            let result = self.node.establish_link(&dest_hash, &mut self.entropy);
                            let _ = reply.send(result);
                            self.drain_outbound().await?;
                        }
                        Some(Command::LinkSend { link_id, plaintext }) => {
                            if let Err(error) =
                                self.node.link_send(&link_id, &plaintext, &mut self.entropy)
                            {
                                self.emit(Event::Error(error)).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::SendResource { link_id, data, reply }) => {
                            let result =
                                self.node.send_resource(&link_id, &data, &mut self.entropy);
                            let _ = reply.send(result);
                            self.drain_outbound().await?;
                        }
                        Some(Command::CloseLink(link_id)) => {
                            self.node.close_link(&link_id);
                            for event in self.node.tick() {
                                self.emit(event).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Command::Shutdown) | None => return Ok(()),
                    }
                }
                inbound = self.inbound.recv() => {
                    match inbound {
                        Some(Inbound::Packet { interface, bytes }) => {
                            for event in self.node.handle_inbound_with_entropy(
                                &bytes,
                                interface,
                                &mut self.entropy,
                            ) {
                                self.emit(event).await;
                            }
                            self.drain_outbound().await?;
                        }
                        Some(Inbound::Closed { interface }) => {
                            self.interfaces.remove(&interface);
                            self.node.unregister_interface(interface);
                            if self.interfaces.is_empty() && !self.keep_alive {
                                return Ok(());
                            }
                        }
                        Some(Inbound::Error { interface, error }) => {
                            self.interfaces.remove(&interface);
                            self.node.unregister_interface(interface);
                            if self.interfaces.is_empty() && !self.keep_alive {
                                return Err(error);
                            }
                            self.emit(Event::Error(NodeError::Unknown)).await;
                        }
                        None => return Ok(()),
                    }
                }
                registration = receive_registration(&mut self.registrations) => {
                    match registration {
                        Some(interface) => {
                            let id = interface.id();
                            if self.interfaces.contains_key(&id) {
                                self.emit(Event::Error(NodeError::Unknown)).await;
                                continue;
                            }
                            self.node.register_interface(id);
                            let sender = spawn_interface(
                                interface,
                                self.inbound_sender.clone(),
                            );
                            self.interfaces.insert(id, sender);
                            if let Some(app_data) = self.announce_data.clone() {
                                let destinations: Vec<_> =
                                    self.node.local_destinations().collect();
                                for destination in destinations {
                                    self.node.send_announce(
                                        &destination,
                                        &app_data,
                                        &mut self.entropy,
                                        id,
                                    );
                                }
                                self.drain_outbound().await?;
                            }
                        }
                        None => {
                            self.registrations = None;
                            if self.interfaces.is_empty() {
                                return Ok(());
                            }
                        }
                    }
                }
                _ = tick.tick() => {
                    for event in self.node.tick_with_entropy(&mut self.entropy) {
                        self.emit(event).await;
                    }
                    self.drain_outbound().await?;
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

fn spawn_interface(
    interface: Box<dyn AsyncInterface>,
    inbound: mpsc::Sender<Inbound>,
) -> mpsc::Sender<Vec<u8>> {
    let id = interface.id();
    let (outbound_tx, outbound_rx) = mpsc::channel(INTERFACE_CAPACITY);
    tokio::spawn(run_interface(id, interface, outbound_rx, inbound));
    outbound_tx
}

async fn receive_registration(
    registrations: &mut Option<mpsc::Receiver<Box<dyn AsyncInterface>>>,
) -> Option<Box<dyn AsyncInterface>> {
    match registrations {
        Some(registrations) => registrations.recv().await,
        None => pending().await,
    }
}

async fn run_interface(
    id: u16,
    mut interface: Box<dyn AsyncInterface>,
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
    async fn dynamically_registered_interface_receives_cached_announce() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
        let (server_stream, _) = listener.accept().await.unwrap();
        let mut peer = connect.await.unwrap().unwrap();

        let mut node = Node::new(Identity::from_private_bytes(&[81u8; 32], &[82u8; 32]));
        node.register_single_destination("dynamic", &["server"]);
        let (events_tx, _events_rx) = mpsc::channel(16);
        let (driver, handle, registrar) = Driver::new_dynamic(node, Vec::new(), events_tx);
        let task = tokio::spawn(driver.run());

        handle.announce_all(b"ready").await.unwrap();
        let id = registrar.allocate_id().unwrap();
        registrar
            .register(Box::new(
                TcpClientInterface::from_stream(server_stream).with_id(id),
            ))
            .await
            .unwrap();
        let announce = timeout(Duration::from_secs(2), peer.recv_packet())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(announce[0] & 0x03, 1);

        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn two_interfaces_announce_receive_and_route_independently() {
        async fn tcp_pair() -> (TcpClientInterface, TcpClientInterface) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
            let (stream, _) = listener.accept().await.unwrap();
            (
                TcpClientInterface::from_stream(stream),
                connect.await.unwrap().unwrap(),
            )
        }

        let (interface_one, mut peer_one) = tcp_pair().await;
        let (interface_two, mut peer_two) = tcp_pair().await;
        let mut node = Node::new(Identity::from_private_bytes(&[91u8; 32], &[92u8; 32]));
        node.register_single_destination("multi", &["local"]);
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (driver, handle) = Driver::new_multi(
            node,
            vec![(1, interface_one), (2, interface_two)],
            events_tx,
        );
        let task = tokio::spawn(driver.run());

        handle.announce_all(b"both").await.unwrap();
        assert!(peer_one.recv_packet().await.unwrap().is_some());
        assert!(peer_two.recv_packet().await.unwrap().is_some());

        let mut remote = Node::new(Identity::from_private_bytes(&[93u8; 32], &[94u8; 32]));
        let remote_dest = remote.register_single_destination("multi", &["remote"]);
        let mut rng = reticulum_node::rng::SeededRng::new(1);
        remote.send_announce(&remote_dest, b"route-one", &mut rng, 0);
        let (_, announce) = remote.poll_outbound().unwrap();
        peer_one.send_packet(&announce).await.unwrap();
        let learned = timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(learned, Event::Announce { dest_hash, .. } if dest_hash == remote_dest));

        handle
            .send(remote_dest, b"only interface one")
            .await
            .unwrap();
        assert!(peer_one.recv_packet().await.unwrap().is_some());
        assert!(
            timeout(Duration::from_millis(100), peer_two.recv_packet())
                .await
                .is_err()
        );

        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn drivers_establish_link_and_exchange_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_interface = connect.await.unwrap().unwrap();
        let server_interface = TcpClientInterface::from_stream(server_stream);

        let mut a_node = Node::new(Identity::from_private_bytes(&[11u8; 32], &[12u8; 32]));
        a_node.register_single_destination("chat", &["link-a"]);
        let mut b_node = Node::new(Identity::from_private_bytes(&[13u8; 32], &[14u8; 32]));
        let b_dest = b_node.register_single_destination("chat", &["link-b"]);
        let (a_events_tx, mut a_events_rx) = mpsc::channel(16);
        let (b_events_tx, mut b_events_rx) = mpsc::channel(16);
        let (a_driver, a_handle) = Driver::new(a_node, client_interface, a_events_tx);
        let (b_driver, b_handle) = Driver::new(b_node, server_interface, b_events_tx);
        let a_task = tokio::spawn(a_driver.run());
        let b_task = tokio::spawn(b_driver.run());

        b_handle.announce_all(b"").await.unwrap();
        let announce = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(announce, Event::Announce { dest_hash, .. } if dest_hash == b_dest));

        let link_id = a_handle.establish_link(b_dest).await.unwrap();
        let b_established = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(b_established, Event::LinkEstablished { link_id: id } if id == link_id));
        let a_established = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(a_established, Event::LinkEstablished { link_id: id } if id == link_id));

        a_handle.link_send(link_id, b"link over tcp").await.unwrap();
        let data = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            data,
            Event::LinkData { link_id: id, plaintext }
                if id == link_id && plaintext == b"link over tcp"
        ));

        b_handle.link_send(link_id, b"link reply").await.unwrap();
        let reply = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            reply,
            Event::LinkData { link_id: id, plaintext }
                if id == link_id && plaintext == b"link reply"
        ));

        let resource = (0..8192)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let resource_hash = a_handle.send_resource(link_id, &resource).await.unwrap();
        let completed = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(Event::ResourceComplete { hash, data, .. }) = b_events_rx.recv().await
                    && hash == resource_hash
                {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(completed, resource);

        a_handle.close_link(link_id).await.unwrap();
        a_handle.shutdown().await.unwrap();
        b_handle.shutdown().await.unwrap();
        a_task.await.unwrap().unwrap();
        b_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn drivers_exchange_proved_group_and_plain_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connect = tokio::spawn(async move { TcpClientInterface::connect(&addr).await });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_interface = connect.await.unwrap().unwrap();
        let server_interface = TcpClientInterface::from_stream(server_stream);

        let group_key = [0xA5; 64];
        let mut a_node = Node::new(Identity::from_private_bytes(&[71u8; 32], &[72u8; 32]));
        let group_dest =
            a_node.register_group_destination("driver_group", &["messages"], group_key);
        let plain_dest = a_node.register_plain_destination("driver_plain", &["messages"]);
        let mut b_node = Node::new(Identity::from_private_bytes(&[73u8; 32], &[74u8; 32]));
        assert_eq!(
            group_dest,
            b_node.register_group_destination("driver_group", &["messages"], group_key)
        );
        assert_eq!(
            plain_dest,
            b_node.register_plain_destination("driver_plain", &["messages"])
        );
        let single_dest = b_node.register_single_destination("driver_proof", &["messages"]);
        assert!(b_node.set_prove(&single_dest, true));

        let (a_events_tx, mut a_events_rx) = mpsc::channel(16);
        let (b_events_tx, mut b_events_rx) = mpsc::channel(16);
        let (a_driver, a_handle) = Driver::new(a_node, client_interface, a_events_tx);
        let (b_driver, b_handle) = Driver::new(b_node, server_interface, b_events_tx);
        let a_task = tokio::spawn(a_driver.run());
        let b_task = tokio::spawn(b_driver.run());

        b_handle.announce_all(b"").await.unwrap();
        let announce = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(announce, Event::Announce { dest_hash, .. } if dest_hash == single_dest));
        let packet_hash = a_handle
            .send_with_receipt(single_dest, b"proved over tcp")
            .await
            .unwrap();
        let message = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(message, Event::Message { plaintext, .. } if plaintext == b"proved over tcp")
        );
        let delivered = timeout(Duration::from_secs(2), a_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered, Event::Delivered { packet_hash });

        a_handle
            .send_group(group_dest, b"group over tcp")
            .await
            .unwrap();
        let group = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(group, Event::Message { plaintext, .. } if plaintext == b"group over tcp")
        );

        a_handle
            .send_plain(plain_dest, b"plain over tcp")
            .await
            .unwrap();
        let plain = timeout(Duration::from_secs(2), b_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(plain, Event::Message { plaintext, .. } if plaintext == b"plain over tcp")
        );

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
        relay_node.enable_transport(true);
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

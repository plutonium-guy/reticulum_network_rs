use reticulum_node::{Event, NodeError, node::Node};
use tokio::sync::mpsc;

use crate::{OsEntropy, tcp::TcpClientInterface};

const INTERFACE_ID: u16 = 0;
const COMMAND_CAPACITY: usize = 32;

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

pub struct Driver {
    node: Node,
    interface: TcpClientInterface,
    entropy: OsEntropy,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
}

impl Driver {
    pub fn new(
        node: Node,
        interface: TcpClientInterface,
        events: mpsc::Sender<Event>,
    ) -> (Self, DriverHandle) {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
        (
            Self {
                node,
                interface,
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
                            for dest_hash in destinations {
                                self.node.send_announce(
                                    &dest_hash,
                                    &app_data,
                                    &mut self.entropy,
                                    INTERFACE_ID,
                                );
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
                inbound = self.interface.recv_packet() => {
                    let Some(packet) = inbound? else {
                        return Ok(());
                    };
                    for event in self.node.handle_inbound(&packet, INTERFACE_ID) {
                        self.emit(event).await;
                    }
                    self.drain_outbound().await?;
                }
            }
        }
    }

    async fn drain_outbound(&mut self) -> std::io::Result<()> {
        while let Some((interface, packet)) = self.node.poll_outbound() {
            if interface != INTERFACE_ID {
                self.emit(Event::Error(NodeError::Unknown)).await;
                continue;
            }
            self.interface.send_packet(&packet).await?;
        }
        Ok(())
    }

    async fn emit(&self, event: Event) {
        let _ = self.events.send(event).await;
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
}

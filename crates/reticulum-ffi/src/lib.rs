use std::sync::{Arc, Mutex, RwLock};

use reticulum_core::identity::Identity;
use reticulum_node::{Event, node::Node};
use reticulum_tokio::{
    SystemClock,
    driver::{Driver, DriverHandle},
    tcp::TcpClientInterface,
};
use tokio::{runtime::Runtime, sync::mpsc};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ReticulumError {
    #[error("identity must contain exactly 64 private-key bytes")]
    InvalidIdentity,
    #[error("destination hash must contain exactly 16 bytes")]
    InvalidDestination,
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is not connected")]
    NotConnected,
    #[error("destinations must be registered before connecting")]
    RegistrationClosed,
    #[error("network operation failed: {reason}")]
    Network { reason: String },
    #[error("Reticulum operation failed: {reason}")]
    Protocol { reason: String },
    #[error("client state is unavailable")]
    StateUnavailable,
}

#[uniffi::export(with_foreign)]
pub trait ReticulumEventHandler: Send + Sync {
    fn on_message(&self, destination_hash: Vec<u8>, plaintext: Vec<u8>);
    fn on_delivered(&self, packet_hash: Vec<u8>);
    fn on_error(&self, message: String);
}

enum ClientState {
    Configuring(Box<Node<SystemClock>>),
    Connected {
        runtime: Arc<Runtime>,
        handle: DriverHandle,
    },
    Closed,
}

#[derive(uniffi::Object)]
pub struct ReticulumClient {
    state: Mutex<ClientState>,
    event_handler: Arc<RwLock<Option<Arc<dyn ReticulumEventHandler>>>>,
}

#[uniffi::export]
impl ReticulumClient {
    #[uniffi::constructor]
    pub fn new(identity_bytes: Vec<u8>) -> Result<Arc<Self>, ReticulumError> {
        let private: [u8; 64] = identity_bytes
            .try_into()
            .map_err(|_| ReticulumError::InvalidIdentity)?;
        let mut encryption = [0u8; 32];
        let mut signing = [0u8; 32];
        encryption.copy_from_slice(&private[..32]);
        signing.copy_from_slice(&private[32..]);
        let identity = Identity::from_private_bytes(&encryption, &signing);
        Ok(Arc::new(Self {
            state: Mutex::new(ClientState::Configuring(Box::new(Node::with_clock(
                identity,
                SystemClock,
            )))),
            event_handler: Arc::new(RwLock::new(None)),
        }))
    }

    pub fn set_event_handler(
        &self,
        handler: Arc<dyn ReticulumEventHandler>,
    ) -> Result<(), ReticulumError> {
        *self
            .event_handler
            .write()
            .map_err(|_| ReticulumError::StateUnavailable)? = Some(handler);
        Ok(())
    }

    pub fn clear_event_handler(&self) -> Result<(), ReticulumError> {
        *self
            .event_handler
            .write()
            .map_err(|_| ReticulumError::StateUnavailable)? = None;
        Ok(())
    }

    pub fn register_single_destination(
        &self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<Vec<u8>, ReticulumError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReticulumError::StateUnavailable)?;
        let ClientState::Configuring(node) = &mut *state else {
            return Err(ReticulumError::RegistrationClosed);
        };
        let aspects: Vec<_> = aspects.iter().map(String::as_str).collect();
        Ok(node
            .register_single_destination(&app_name, &aspects)
            .to_vec())
    }

    pub fn connect_tcp(&self, address: String) -> Result<(), ReticulumError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReticulumError::StateUnavailable)?;
        if matches!(&*state, ClientState::Connected { .. }) {
            return Err(ReticulumError::AlreadyConnected);
        }
        let ClientState::Configuring(node) = core::mem::replace(&mut *state, ClientState::Closed)
        else {
            return Err(ReticulumError::NotConnected);
        };

        let runtime = Arc::new(Runtime::new().map_err(|error| ReticulumError::Network {
            reason: error.to_string(),
        })?);
        let interface = match runtime.block_on(TcpClientInterface::connect(&address)) {
            Ok(interface) => interface,
            Err(error) => {
                *state = ClientState::Configuring(node);
                return Err(ReticulumError::Network {
                    reason: error.to_string(),
                });
            }
        };
        let (events_tx, events_rx) = mpsc::channel(64);
        let (driver, handle) = {
            let _runtime_context = runtime.enter();
            Driver::new(*node, interface, events_tx)
        };
        runtime.spawn(run_events(events_rx, Arc::clone(&self.event_handler)));
        runtime.spawn(async move {
            if let Err(error) = driver.run().await {
                let _ = error;
            }
        });
        *state = ClientState::Connected { runtime, handle };
        Ok(())
    }

    pub fn announce(&self, app_data: Vec<u8>) -> Result<(), ReticulumError> {
        let (runtime, handle) = self.connection()?;
        runtime
            .block_on(handle.announce_all(&app_data))
            .map_err(|_| ReticulumError::NotConnected)
    }

    pub fn send(
        &self,
        destination_hash: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, ReticulumError> {
        let destination: [u8; 16] = destination_hash
            .try_into()
            .map_err(|_| ReticulumError::InvalidDestination)?;
        let (runtime, handle) = self.connection()?;
        runtime
            .block_on(handle.send_with_receipt(destination, &plaintext))
            .map(|hash| hash.to_vec())
            .map_err(|error| ReticulumError::Protocol {
                reason: format!("{error:?}"),
            })
    }

    pub fn disconnect(&self) -> Result<(), ReticulumError> {
        let (runtime, handle) = self.connection()?;
        runtime
            .block_on(handle.shutdown())
            .map_err(|_| ReticulumError::NotConnected)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReticulumError::StateUnavailable)?;
        *state = ClientState::Closed;
        Ok(())
    }
}

impl ReticulumClient {
    fn connection(&self) -> Result<(Arc<Runtime>, DriverHandle), ReticulumError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReticulumError::StateUnavailable)?;
        let ClientState::Connected { runtime, handle } = &*state else {
            return Err(ReticulumError::NotConnected);
        };
        Ok((Arc::clone(runtime), handle.clone()))
    }
}

async fn run_events(
    mut events: mpsc::Receiver<Event>,
    handler: Arc<RwLock<Option<Arc<dyn ReticulumEventHandler>>>>,
) {
    while let Some(event) = events.recv().await {
        let callback = handler.read().ok().and_then(|guard| guard.clone());
        let Some(callback) = callback else {
            continue;
        };
        match event {
            Event::Message {
                dest_hash,
                plaintext,
            } => callback.on_message(dest_hash.to_vec(), plaintext),
            Event::Delivered { packet_hash } => callback.on_delivered(packet_hash.to_vec()),
            Event::Error(error) => callback.on_error(format!("{error:?}")),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::TcpListener,
        sync::{Condvar, Mutex as StdMutex},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    #[derive(Default)]
    struct RecordingHandler {
        messages: StdMutex<Vec<Vec<u8>>>,
        changed: Condvar,
    }

    impl ReticulumEventHandler for RecordingHandler {
        fn on_message(&self, _destination_hash: Vec<u8>, plaintext: Vec<u8>) {
            self.messages.lock().unwrap().push(plaintext);
            self.changed.notify_all();
        }

        fn on_delivered(&self, _packet_hash: Vec<u8>) {}

        fn on_error(&self, _message: String) {}
    }

    impl RecordingHandler {
        fn wait_for(&self, expected: &[u8]) {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut messages = self.messages.lock().unwrap();
            while !messages.iter().any(|message| message == expected) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "timed out waiting for callback");
                let (next, timeout) = self.changed.wait_timeout(messages, remaining).unwrap();
                messages = next;
                assert!(!timeout.timed_out(), "timed out waiting for callback");
            }
        }
    }

    fn start_relay() -> (String, thread::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = thread::spawn(move || {
            let (a, _) = listener.accept()?;
            let (b, _) = listener.accept()?;
            let a_reader = a.try_clone()?;
            let b_reader = b.try_clone()?;
            let a_to_b = thread::spawn(move || io::copy(&mut &a_reader, &mut &b));
            let b_to_a = thread::spawn(move || io::copy(&mut &b_reader, &mut &a));
            let _ = a_to_b.join();
            let _ = b_to_a.join();
            Ok(())
        });
        (address, task)
    }

    fn client(seed: u8) -> Arc<ReticulumClient> {
        let mut identity = vec![seed; 64];
        identity[32..].fill(seed.wrapping_add(1));
        ReticulumClient::new(identity).unwrap()
    }

    fn send_after_path(client: &ReticulumClient, destination: &[u8], message: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match client.send(destination.to_vec(), message.to_vec()) {
                Ok(hash) => return hash,
                Err(ReticulumError::Protocol { .. }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                result => panic!("send failed: {result:?}"),
            }
        }
    }

    #[test]
    fn two_exported_facades_exchange_messages_over_tcp() {
        let (address, relay) = start_relay();
        let a = client(1);
        let b = client(3);
        let a_destination = a
            .register_single_destination("ffi".into(), vec!["message".into()])
            .unwrap();
        let b_destination = b
            .register_single_destination("ffi".into(), vec!["message".into()])
            .unwrap();
        let a_handler = Arc::new(RecordingHandler::default());
        let b_handler = Arc::new(RecordingHandler::default());
        a.set_event_handler(a_handler.clone()).unwrap();
        b.set_event_handler(b_handler.clone()).unwrap();
        a.connect_tcp(address.clone()).unwrap();
        b.connect_tcp(address).unwrap();
        a.announce(Vec::new()).unwrap();
        b.announce(Vec::new()).unwrap();

        assert_eq!(
            send_after_path(&a, &b_destination, b"hello from a").len(),
            32
        );
        assert_eq!(
            send_after_path(&b, &a_destination, b"hello from b").len(),
            32
        );
        a_handler.wait_for(b"hello from b");
        b_handler.wait_for(b"hello from a");

        a.disconnect().unwrap();
        b.disconnect().unwrap();
        relay.join().unwrap().unwrap();
    }
}

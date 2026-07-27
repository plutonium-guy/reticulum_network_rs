use std::io;

use async_trait::async_trait;
use reticulum_interface::ifac::{
    DEFAULT_IFAC_SIZE, IFAC_KEY_SIZE, apply_with_size, derive_key, strip_with_size,
};

/// Object-safe async packet interface used by the runtime driver.
///
/// Implementations own transport framing. Callers always exchange complete,
/// unframed Reticulum packets.
#[async_trait]
pub trait AsyncInterface: Send {
    fn id(&self) -> u16;

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>>;

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()>;
}

#[derive(Clone)]
pub struct IfacConfig {
    key: [u8; IFAC_KEY_SIZE],
    size: usize,
}

impl IfacConfig {
    pub fn new(network_name: &str, passphrase: &str) -> Self {
        Self {
            key: derive_key(network_name, passphrase),
            size: DEFAULT_IFAC_SIZE,
        }
    }

    pub fn with_size(mut self, size: usize) -> io::Result<Self> {
        if !(1..=64).contains(&size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IFAC size must be between 1 and 64 bytes",
            ));
        }
        self.size = size;
        Ok(self)
    }
}

pub fn with_ifac(
    interface: Box<dyn AsyncInterface>,
    config: IfacConfig,
) -> Box<dyn AsyncInterface> {
    Box::new(IfacInterface {
        inner: interface,
        config,
    })
}

struct IfacInterface {
    inner: Box<dyn AsyncInterface>,
    config: IfacConfig,
}

#[async_trait]
impl AsyncInterface for IfacInterface {
    fn id(&self) -> u16 {
        self.inner.id()
    }

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let Some(wire) = self.inner.recv_packet().await? else {
                return Ok(None);
            };
            if let Ok(plain) = strip_with_size(&wire, &self.config.key, self.config.size) {
                return Ok(Some(plain));
            }
        }
    }

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
        let wire = apply_with_size(raw, &self.config.key, self.config.size)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))?;
        self.inner.send_packet(&wire).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    struct MemoryInterface {
        id: u16,
        inbound: VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait]
    impl AsyncInterface for MemoryInterface {
        fn id(&self) -> u16 {
            self.id
        }

        async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.inbound.pop_front())
        }

        async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(raw.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn ifac_wrapper_transforms_and_rejects_mismatches() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut sender = with_ifac(
            Box::new(MemoryInterface {
                id: 7,
                inbound: VecDeque::new(),
                sent: Arc::clone(&sent),
            }),
            IfacConfig::new("mesh", "secret"),
        );
        sender.send_packet(b"\x08\x00packet").await.unwrap();
        let wire = sent.lock().unwrap()[0].clone();
        assert_ne!(wire, b"\x08\x00packet");
        assert_ne!(wire[0] & 0x80, 0);

        let mut receiver = with_ifac(
            Box::new(MemoryInterface {
                id: 7,
                inbound: VecDeque::from([wire.clone()]),
                sent: Arc::new(Mutex::new(Vec::new())),
            }),
            IfacConfig::new("mesh", "secret"),
        );
        assert_eq!(
            receiver.recv_packet().await.unwrap().unwrap(),
            b"\x08\x00packet"
        );

        let mut mismatch = with_ifac(
            Box::new(MemoryInterface {
                id: 7,
                inbound: VecDeque::from([wire]),
                sent: Arc::new(Mutex::new(Vec::new())),
            }),
            IfacConfig::new("mesh", "wrong"),
        );
        assert_eq!(mismatch.recv_packet().await.unwrap(), None);
    }
}

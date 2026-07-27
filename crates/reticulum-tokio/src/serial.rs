use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use reticulum_interface::{
    Framing, Interface,
    kiss::{self, FEND},
};
use tokio::sync::mpsc;

const SERIAL_HW_MTU: usize = 564;
const READ_CAPACITY: usize = SERIAL_HW_MTU * 2 + 3;

/// KISS-framed Reticulum packets over a blocking serial device.
///
/// The blocking reader is isolated on a dedicated OS thread; writes use
/// Tokio's blocking pool so neither direction stalls the async driver.
pub struct SerialInterface {
    id: u16,
    writer: Arc<Mutex<Box<dyn serialport::SerialPort>>>,
    inbound: mpsc::Receiver<io::Result<Vec<u8>>>,
}

impl SerialInterface {
    pub fn open(path: &str, baud: u32) -> io::Result<Self> {
        let port = serialport::new(path, baud)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(serial_error)?;
        let mut reader = port.try_clone().map_err(serial_error)?;
        let writer = Arc::new(Mutex::new(port));
        let (inbound_tx, inbound) = mpsc::channel(32);

        std::thread::Builder::new()
            .name("reticulum-serial-reader".to_owned())
            .spawn(move || {
                let mut chunk = [0u8; 512];
                let mut framed = Vec::with_capacity(READ_CAPACITY);
                loop {
                    match reader.read(&mut chunk) {
                        Ok(read) => {
                            for &byte in &chunk[..read] {
                                if byte == FEND {
                                    if framed.len() >= 2 {
                                        framed.push(FEND);
                                        if let Some(packet) = kiss::deframe(&framed)
                                            && inbound_tx.blocking_send(Ok(packet)).is_err()
                                        {
                                            return;
                                        }
                                    }
                                    framed.clear();
                                    framed.push(FEND);
                                } else if !framed.is_empty() {
                                    if framed.len() < READ_CAPACITY {
                                        framed.push(byte);
                                    } else {
                                        framed.clear();
                                    }
                                }
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                            ) => {}
                        Err(error) => {
                            let _ = inbound_tx.blocking_send(Err(error));
                            return;
                        }
                    }
                }
            })?;

        Ok(Self {
            id: 0,
            writer,
            inbound,
        })
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
}

impl Interface for SerialInterface {
    const FRAMING: Framing = Framing::Kiss;
    const HW_MTU: usize = SERIAL_HW_MTU;
}

#[async_trait]
impl crate::interface::AsyncInterface for SerialInterface {
    fn id(&self) -> u16 {
        self.id
    }

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.inbound.recv().await.transpose()
    }

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
        if raw.len() > SERIAL_HW_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serial packet exceeds RNS KISS hardware MTU",
            ));
        }
        let writer = Arc::clone(&self.writer);
        let framed = kiss::frame(raw);
        tokio::task::spawn_blocking(move || {
            let mut writer = writer
                .lock()
                .map_err(|_| io::Error::other("serial writer lock poisoned"))?;
            writer.write_all(&framed)
        })
        .await
        .map_err(|error| io::Error::other(format!("serial writer task failed: {error}")))?
    }
}

fn serial_error(error: serialport::Error) -> io::Error {
    io::Error::other(error)
}

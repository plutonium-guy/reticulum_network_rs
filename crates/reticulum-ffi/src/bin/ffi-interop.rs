use std::{
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use reticulum_ffi::{ReticulumClient, ReticulumError, ReticulumEventHandler};

#[derive(Default)]
struct Evidence {
    received: Mutex<bool>,
    changed: Condvar,
}

impl ReticulumEventHandler for Evidence {
    fn on_message(&self, _destination_hash: Vec<u8>, plaintext: Vec<u8>) {
        println!("FFI_RECEIVED {}", String::from_utf8_lossy(&plaintext));
        *self.received.lock().expect("evidence lock poisoned") = true;
        self.changed.notify_all();
    }

    fn on_delivered(&self, packet_hash: Vec<u8>) {
        println!("FFI_DELIVERED {}", hex::encode(packet_hash));
    }

    fn on_error(&self, message: String) {
        eprintln!("FFI_ERROR {message}");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let address = args.next().ok_or("usage: ffi-interop <address> <dest>")?;
    let python_destination =
        hex::decode(args.next().ok_or("usage: ffi-interop <address> <dest>")?)?;

    let mut identity = vec![0x31; 64];
    identity[32..].fill(0x32);
    let client = ReticulumClient::new(identity)?;
    let destination =
        client.register_single_destination("ffi_mobile".to_owned(), vec!["message".to_owned()])?;
    let evidence = Arc::new(Evidence::default());
    client.set_event_handler(evidence.clone())?;
    client.connect_tcp(address)?;
    println!("FFI_DESTINATION {}", hex::encode(destination));

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut sent = false;
    while Instant::now() < deadline {
        client.announce(b"ffi interop client".to_vec())?;
        if !sent {
            match client.send(
                python_destination.clone(),
                b"hello from ffi to python".to_vec(),
            ) {
                Ok(_) => {
                    println!("FFI_SENT hello from ffi to python");
                    sent = true;
                }
                Err(ReticulumError::Protocol { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let received = evidence.received.lock().expect("evidence lock poisoned");
        let (received, _) = evidence
            .changed
            .wait_timeout(received, Duration::from_millis(250))
            .expect("evidence lock poisoned");
        if sent && *received {
            client.disconnect()?;
            return Ok(());
        }
        drop(received);
        thread::sleep(Duration::from_millis(50));
    }

    Err("timed out waiting for bidirectional FFI exchange".into())
}

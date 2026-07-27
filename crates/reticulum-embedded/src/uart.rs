use alloc::vec::Vec;

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};
use embedded_io_async::{Read, Write};
use reticulum_core::EntropySource;
use reticulum_interface::kiss::{CMD_DATA, FEND, FESC, TFEND, TFESC, frame};
use reticulum_node::{Clock, Event, node::Node};

/// Incremental, allocation-bounded decoder for a KISS byte stream.
pub struct KissStreamDecoder {
    packet: Vec<u8>,
    max_packet_len: usize,
    in_frame: bool,
    has_command: bool,
    escaped: bool,
    invalid: bool,
}

impl KissStreamDecoder {
    pub fn new(max_packet_len: usize) -> Self {
        Self {
            packet: Vec::new(),
            max_packet_len,
            in_frame: false,
            has_command: false,
            escaped: false,
            invalid: false,
        }
    }

    /// Consume one serial byte, returning a complete port-zero data packet.
    ///
    /// Malformed, command, and oversized frames are discarded at the next
    /// frame boundary without panicking or allowing unbounded allocation.
    pub fn push(&mut self, byte: u8) -> Option<Vec<u8>> {
        if byte == FEND {
            let complete = if self.in_frame
                && self.has_command
                && !self.escaped
                && !self.invalid
                && !self.packet.is_empty()
            {
                Some(core::mem::take(&mut self.packet))
            } else {
                self.packet.clear();
                None
            };
            self.in_frame = true;
            self.has_command = false;
            self.escaped = false;
            self.invalid = false;
            return complete;
        }

        if !self.in_frame || self.invalid {
            return None;
        }
        if !self.has_command {
            self.has_command = true;
            self.invalid = byte & 0x0f != CMD_DATA;
            return None;
        }

        let decoded = if self.escaped {
            self.escaped = false;
            match byte {
                TFEND => FEND,
                TFESC => FESC,
                _ => {
                    self.invalid = true;
                    return None;
                }
            }
        } else if byte == FESC {
            self.escaped = true;
            return None;
        } else {
            byte
        };

        if self.packet.len() == self.max_packet_len {
            self.packet.clear();
            self.invalid = true;
        } else {
            self.packet.push(decoded);
        }
        None
    }
}

/// Feed serial bytes into a node and return the protocol events they produced.
pub fn pump_inbound<C: Clock, R: EntropySource>(
    node: &mut Node<C>,
    entropy: &mut R,
    decoder: &mut KissStreamDecoder,
    interface: u16,
    bytes: &[u8],
) -> Vec<Event> {
    let mut events = Vec::new();
    for &byte in bytes {
        if let Some(packet) = decoder.push(byte) {
            events.extend(node.handle_inbound_with_entropy(&packet, interface, entropy));
        }
    }
    events
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UartPumpError<E> {
    Io(E),
    EndOfStream,
}

/// Run a Reticulum node over an async UART using KISS framing.
///
/// The selected HAL UART only needs to implement `embedded-io-async`. Embassy
/// timers ensure protocol maintenance continues while the UART is idle.
pub async fn run_uart<U, C, R, F>(
    uart: &mut U,
    node: &mut Node<C>,
    entropy: &mut R,
    interface: u16,
    max_packet_len: usize,
    tick_every: Duration,
    mut on_event: F,
) -> Result<(), UartPumpError<U::Error>>
where
    U: Read + Write,
    C: Clock,
    R: EntropySource,
    F: FnMut(Event),
{
    node.register_interface(interface);
    let mut decoder = KissStreamDecoder::new(max_packet_len);
    let mut input = [0u8; 256];

    loop {
        match select(uart.read(&mut input), Timer::after(tick_every)).await {
            Either::First(Ok(0)) => return Err(UartPumpError::EndOfStream),
            Either::First(Ok(read)) => {
                for event in pump_inbound(node, entropy, &mut decoder, interface, &input[..read]) {
                    on_event(event);
                }
            }
            Either::First(Err(error)) => return Err(UartPumpError::Io(error)),
            Either::Second(_) => {
                for event in node.tick_with_entropy(entropy) {
                    on_event(event);
                }
            }
        }

        while let Some((outbound_interface, packet)) = node.poll_outbound() {
            if outbound_interface == interface {
                uart.write_all(&frame(&packet))
                    .await
                    .map_err(UartPumpError::Io)?;
            }
        }
        uart.flush().await.map_err(UartPumpError::Io)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use reticulum_core::identity::Identity;
    use reticulum_node::TestClock;

    struct TestEntropy(u8);

    impl EntropySource for TestEntropy {
        fn fill(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
        }
    }

    fn identity(seed: u8) -> Identity {
        Identity::from_private_bytes(&[seed; 32], &[seed.wrapping_add(1); 32])
    }

    #[test]
    fn decoder_handles_partial_coalesced_and_escaped_frames() {
        let first = frame(&[1, FEND, 2, FESC]);
        let second = frame(&[3, 4]);
        let mut decoder = KissStreamDecoder::new(64);
        let mut packets = Vec::new();

        for chunk in first
            .iter()
            .chain(second.iter())
            .copied()
            .collect::<Vec<_>>()
            .chunks(3)
        {
            for &byte in chunk {
                if let Some(packet) = decoder.push(byte) {
                    packets.push(packet);
                }
            }
        }

        assert_eq!(packets, [vec![1, FEND, 2, FESC], vec![3, 4]]);
    }

    #[test]
    fn decoder_recovers_after_oversized_and_malformed_frames() {
        let mut decoder = KissStreamDecoder::new(2);
        let stream = [
            FEND, CMD_DATA, 1, 2, 3, FEND, CMD_DATA, FESC, 1, FEND, FEND, CMD_DATA, 9, FEND,
        ];
        let packets: Vec<_> = stream
            .into_iter()
            .filter_map(|byte| decoder.push(byte))
            .collect();
        assert_eq!(packets, [vec![9]]);
    }

    #[test]
    fn inbound_pump_delivers_an_announce_to_the_node() {
        let mut sender = Node::with_clock(identity(1), TestClock::new(10));
        let destination = sender.register_single_destination("embedded", &["message"]);
        sender.register_interface(7);
        let mut sender_entropy = TestEntropy(0);
        sender.send_announce(&destination, b"", &mut sender_entropy, 7);
        let (_, announce) = sender.poll_outbound().unwrap();

        let mut receiver = Node::with_clock(identity(3), TestClock::new(10));
        receiver.register_interface(7);
        let mut receiver_entropy = TestEntropy(50);
        let mut decoder = KissStreamDecoder::new(1024);
        let framed = frame(&announce);
        let split = framed.len() / 2;
        assert!(
            pump_inbound(
                &mut receiver,
                &mut receiver_entropy,
                &mut decoder,
                7,
                &framed[..split],
            )
            .is_empty()
        );
        let events = pump_inbound(
            &mut receiver,
            &mut receiver_entropy,
            &mut decoder,
            7,
            &framed[split..],
        );

        assert!(events.iter().any(
            |event| matches!(event, Event::Announce { dest_hash, .. } if dest_hash == &destination)
        ));
    }
}

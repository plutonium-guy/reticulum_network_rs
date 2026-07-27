use reticulum_interface::hdlc::{FLAG, deframe};

const MAX_BUFFER: usize = 512 * 1024;

/// Incremental HDLC decoder for arbitrary WebSocket message boundaries.
#[derive(Debug, Default)]
pub struct HdlcStreamDecoder {
    buffer: Vec<u8>,
}

impl HdlcStreamDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() > MAX_BUFFER {
            self.buffer.clear();
            return Vec::new();
        }

        let mut packets = Vec::new();
        loop {
            let Some(start) = self.buffer.iter().position(|byte| *byte == FLAG) else {
                self.buffer.clear();
                break;
            };
            if start > 0 {
                self.buffer.drain(..start);
            }
            let Some(end) = self.buffer[1..]
                .iter()
                .position(|byte| *byte == FLAG)
                .map(|offset| offset + 1)
            else {
                break;
            };
            let framed = self.buffer[..=end].to_vec();
            self.buffer.drain(..end);
            if framed.len() == 2 {
                continue;
            }
            if let Some(packet) = deframe(&framed) {
                packets.push(packet);
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_interface::hdlc::frame;

    #[test]
    fn decodes_partial_and_coalesced_websocket_chunks() {
        let first = frame(b"first");
        let second = frame(&[FLAG, 0x11, 0x7D]);
        let mut stream = Vec::new();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&second);

        let mut decoder = HdlcStreamDecoder::default();
        assert!(decoder.push(&stream[..3]).is_empty());
        assert_eq!(
            decoder.push(&stream[3..]),
            [b"first".to_vec(), vec![FLAG, 0x11, 0x7D]]
        );
    }
}

use crate::CoreError;
use alloc::vec::Vec;

pub const DATA: u8 = 0x00;
pub const ANNOUNCE: u8 = 0x01;
pub const LINKREQUEST: u8 = 0x02;
pub const PROOF: u8 = 0x03;

const HEADER_1: u8 = 0;
const HEADER_2: u8 = 1;
const ADDR_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header_type: u8,
    pub packet_type: u8,
    pub dest_type: u8,
    pub propagation: u8,
    pub context_flag: bool,
    pub ifac: bool,
    pub hops: u8,
    pub dest_hash: Vec<u8>,
    pub context: u8,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Packet, CoreError> {
        if bytes.len() < 2 {
            return Err(CoreError::Truncated);
        }
        let flags = bytes[0];
        let ifac = (flags >> 7) & 0x1 == 1;
        let header_type = (flags >> 6) & 0x1;
        let context_flag = (flags >> 5) & 0x1 == 1;
        let propagation = (flags >> 4) & 0x1;
        let dest_type = (flags >> 2) & 0x3;
        let packet_type = flags & 0x3;
        let hops = bytes[1];

        let addr_bytes = match header_type {
            HEADER_1 => ADDR_LEN,
            _ => ADDR_LEN * 2, // HEADER_2
        };
        let mut idx = 2usize;
        if bytes.len() < idx + addr_bytes + 1 {
            return Err(CoreError::Truncated);
        }
        // HEADER_2: only the destination half of the address block is kept; the transport-ID half is discarded (revisited when transport/HEADER_2 support lands).
        let dest_hash = if header_type == HEADER_2 {
            bytes[idx + ADDR_LEN..idx + 2 * ADDR_LEN].to_vec()
        } else {
            bytes[idx..idx + ADDR_LEN].to_vec()
        };
        idx += addr_bytes;
        let context = bytes[idx];
        idx += 1;
        let data = bytes[idx..].to_vec();

        Ok(Packet {
            ifac,
            header_type,
            context_flag,
            propagation,
            dest_type,
            packet_type,
            hops,
            dest_hash,
            context,
            data,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let flags = ((self.ifac as u8) << 7)
            | ((self.header_type & 0x1) << 6)
            | ((self.context_flag as u8) << 5)
            | ((self.propagation & 0x1) << 4)
            | ((self.dest_type & 0x3) << 2)
            | (self.packet_type & 0x3);
        let mut out = Vec::with_capacity(2 + self.dest_hash.len() + 1 + self.data.len());
        out.push(flags);
        out.push(self.hops);
        out.extend_from_slice(&self.dest_hash);
        out.push(self.context);
        out.extend_from_slice(&self.data);
        out
    }
}

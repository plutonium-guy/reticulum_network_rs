use crate::CoreError;
use alloc::vec::Vec;

pub const DATA: u8 = 0x00;
pub const ANNOUNCE: u8 = 0x01;
pub const LINKREQUEST: u8 = 0x02;
pub const PROOF: u8 = 0x03;
/// RNS destination type value for a single-identity destination.
pub const SINGLE: u8 = 0x00;
pub const PLAIN: u8 = 0x02;
/// Measured from RNS 1.4.1 `Destination.LINK`.
pub const LINK: u8 = 0x03;

pub const HEADER_1: u8 = 0;
pub const HEADER_2: u8 = 1;
pub const BROADCAST: u8 = 0;
pub const TRANSPORT: u8 = 1;
pub const PATH_RESPONSE: u8 = 0x0B;
pub const KEEPALIVE: u8 = 0xFA;
pub const LINKCLOSE: u8 = 0xFC;
pub const LRRTT: u8 = 0xFE;
pub const LRPROOF: u8 = 0xFF;
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
    /// Next-hop transport identity for HEADER_2 packets.
    pub transport_id: Option<[u8; 16]>,
    pub dest_hash: Vec<u8>,
    pub context: u8,
    pub data: Vec<u8>,
}

impl Packet {
    pub const SINGLE: u8 = crate::packet::SINGLE;

    pub fn announce(dest_hash: &[u8; 16], payload: Vec<u8>) -> Packet {
        Packet {
            ifac: false,
            header_type: HEADER_1,
            context_flag: false,
            propagation: 0,
            dest_type: Self::SINGLE,
            packet_type: ANNOUNCE,
            hops: 0,
            transport_id: None,
            dest_hash: dest_hash.to_vec(),
            context: 0,
            data: payload,
        }
    }

    pub fn data_single(dest_hash: &[u8; 16], ciphertext: Vec<u8>) -> Packet {
        Packet {
            ifac: false,
            header_type: HEADER_1,
            context_flag: false,
            propagation: 0,
            dest_type: Self::SINGLE,
            packet_type: DATA,
            hops: 0,
            transport_id: None,
            dest_hash: dest_hash.to_vec(),
            context: 0,
            data: ciphertext,
        }
    }

    pub fn path_request_destination_hash() -> [u8; 16] {
        let name_hash = crate::destination::name_hash("rnstransport", &["path", "request"]);
        crate::hash::truncated_hash(&name_hash)
    }

    pub fn path_request(
        target: &[u8; 16],
        requester_transport_id: Option<&[u8; 16]>,
        tag: &[u8; 16],
    ) -> Packet {
        let mut data = Vec::with_capacity(if requester_transport_id.is_some() {
            48
        } else {
            32
        });
        data.extend_from_slice(target);
        if let Some(requester) = requester_transport_id {
            data.extend_from_slice(requester);
        }
        data.extend_from_slice(tag);
        Packet {
            ifac: false,
            header_type: HEADER_1,
            context_flag: false,
            propagation: BROADCAST,
            dest_type: PLAIN,
            packet_type: DATA,
            hops: 0,
            transport_id: None,
            dest_hash: Self::path_request_destination_hash().to_vec(),
            context: 0,
            data,
        }
    }

    pub fn link_request(dest_hash: &[u8; 16], payload: Vec<u8>) -> Packet {
        Self::new_header1(SINGLE, LINKREQUEST, dest_hash, 0, payload)
    }

    pub fn proof(link_id: &[u8; 16], proof_data: Vec<u8>, context: u8) -> Packet {
        Self::new_header1(LINK, PROOF, link_id, context, proof_data)
    }

    pub fn link_data(link_id: &[u8; 16], ciphertext: Vec<u8>) -> Packet {
        Self::link_data_with_context(link_id, ciphertext, 0)
    }

    pub fn link_data_with_context(link_id: &[u8; 16], ciphertext: Vec<u8>, context: u8) -> Packet {
        Self::new_header1(LINK, DATA, link_id, context, ciphertext)
    }

    fn new_header1(
        dest_type: u8,
        packet_type: u8,
        dest_hash: &[u8; 16],
        context: u8,
        data: Vec<u8>,
    ) -> Packet {
        Packet {
            ifac: false,
            header_type: HEADER_1,
            context_flag: false,
            propagation: BROADCAST,
            dest_type,
            packet_type,
            hops: 0,
            transport_id: None,
            dest_hash: dest_hash.to_vec(),
            context,
            data,
        }
    }

    pub fn hashable_part(&self) -> Vec<u8> {
        let mut hashable = Vec::with_capacity(1 + self.dest_hash.len() + 1 + self.data.len());
        hashable.push(((self.dest_type & 0x3) << 2) | (self.packet_type & 0x3));
        hashable.extend_from_slice(&self.dest_hash);
        hashable.push(self.context);
        hashable.extend_from_slice(&self.data);
        hashable
    }

    /// RNS packet hash, excluding mutable hop and transport-routing fields.
    pub fn packet_hash(&self) -> [u8; 16] {
        crate::hash::truncated_hash(&self.hashable_part())
    }

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
        let transport_id = if header_type == HEADER_2 {
            Some(
                bytes[idx..idx + ADDR_LEN]
                    .try_into()
                    .map_err(|_| CoreError::Truncated)?,
            )
        } else {
            None
        };
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
            transport_id,
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
        let transport_len = if self.header_type == HEADER_2 {
            ADDR_LEN
        } else {
            0
        };
        let mut out =
            Vec::with_capacity(2 + transport_len + self.dest_hash.len() + 1 + self.data.len());
        out.push(flags);
        out.push(self.hops);
        if self.header_type == HEADER_2
            && let Some(transport_id) = self.transport_id
        {
            out.extend_from_slice(&transport_id);
        }
        out.extend_from_slice(&self.dest_hash);
        out.push(self.context);
        out.extend_from_slice(&self.data);
        out
    }
}

use alloc::vec::Vec;

use reticulum_core::{
    CoreError,
    hash::full_hash,
    identity::{Identity, PublicIdentity},
};
use rmp::encode::{write_array_len, write_bin, write_f64};

pub const DESTINATION_LENGTH: usize = 16;
pub const SIGNATURE_LENGTH: usize = 64;
pub const HASH_LENGTH: usize = 32;
pub const HEADER_LENGTH: usize = DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH;

#[derive(Debug, Clone, PartialEq)]
pub struct LxmfMessage {
    pub destination: [u8; DESTINATION_LENGTH],
    pub source: [u8; DESTINATION_LENGTH],
    pub timestamp: f64,
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    /// One complete MessagePack map value, retained byte-for-byte.
    pub fields: Vec<u8>,
    /// Optional LXMF delivery stamp (32-byte PoW or 16-byte ticket stamp).
    pub stamp: Option<Vec<u8>>,
    pub signature: [u8; SIGNATURE_LENGTH],
    pub hash: [u8; HASH_LENGTH],
}

impl LxmfMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        source_identity: &Identity,
        destination: [u8; DESTINATION_LENGTH],
        source: [u8; DESTINATION_LENGTH],
        timestamp: f64,
        title: &[u8],
        content: &[u8],
        fields_msgpack: &[u8],
    ) -> Self {
        let payload = encode_payload(timestamp, title, content, fields_msgpack);
        let hashed_part = hashed_part(&destination, &source, &payload);
        let hash = full_hash(&hashed_part);
        let mut signed_part = Vec::with_capacity(hashed_part.len() + HASH_LENGTH);
        signed_part.extend_from_slice(&hashed_part);
        signed_part.extend_from_slice(&hash);

        Self {
            destination,
            source,
            timestamp,
            title: title.to_vec(),
            content: content.to_vec(),
            fields: fields_msgpack.to_vec(),
            stamp: None,
            signature: source_identity.sign(&signed_part),
            hash,
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        let payload = self.wire_payload();
        let mut packed = Vec::with_capacity(HEADER_LENGTH + payload.len());
        packed.extend_from_slice(&self.destination);
        packed.extend_from_slice(&self.source);
        packed.extend_from_slice(&self.signature);
        packed.extend_from_slice(&payload);
        packed
    }

    pub fn unpack(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(CoreError::Truncated);
        }
        let destination = bytes[..DESTINATION_LENGTH]
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        let source = bytes[DESTINATION_LENGTH..DESTINATION_LENGTH * 2]
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        let signature = bytes[DESTINATION_LENGTH * 2..HEADER_LENGTH]
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        let decoded = decode_payload(&bytes[HEADER_LENGTH..])?;
        let payload = encode_payload(
            decoded.timestamp,
            &decoded.title,
            &decoded.content,
            &decoded.fields,
        );
        let hash = full_hash(&hashed_part(&destination, &source, &payload));

        Ok(Self {
            destination,
            source,
            timestamp: decoded.timestamp,
            title: decoded.title,
            content: decoded.content,
            fields: decoded.fields,
            stamp: decoded.stamp,
            signature,
            hash,
        })
    }

    pub fn verify(&self, source_public: &PublicIdentity) -> Result<(), CoreError> {
        let payload = self.payload();
        let hashed_part = hashed_part(&self.destination, &self.source, &payload);
        let hash = full_hash(&hashed_part);
        if hash != self.hash {
            return Err(CoreError::BadSignature);
        }
        let mut signed_part = Vec::with_capacity(hashed_part.len() + HASH_LENGTH);
        signed_part.extend_from_slice(&hashed_part);
        signed_part.extend_from_slice(&hash);
        source_public.verify(&signed_part, &self.signature)
    }

    pub fn payload(&self) -> Vec<u8> {
        encode_payload(self.timestamp, &self.title, &self.content, &self.fields)
    }

    fn wire_payload(&self) -> Vec<u8> {
        match self.stamp.as_deref() {
            None => self.payload(),
            Some(stamp) => {
                let mut payload = Vec::new();
                write_array_len(&mut payload, 5).expect("writing to Vec cannot fail");
                write_f64(&mut payload, self.timestamp).expect("writing to Vec cannot fail");
                write_bin(&mut payload, &self.title).expect("writing to Vec cannot fail");
                write_bin(&mut payload, &self.content).expect("writing to Vec cannot fail");
                payload.extend_from_slice(&self.fields);
                write_bin(&mut payload, stamp).expect("writing to Vec cannot fail");
                payload
            }
        }
    }
}

struct DecodedPayload {
    timestamp: f64,
    title: Vec<u8>,
    content: Vec<u8>,
    fields: Vec<u8>,
    stamp: Option<Vec<u8>>,
}

fn decode_payload(payload: &[u8]) -> Result<DecodedPayload, CoreError> {
    let mut position = 0;
    let length = read_collection_len(payload, &mut position, 0x90, 0xdc, 0xdd)?;
    if !matches!(length, 4 | 5) {
        return Err(CoreError::InvalidField);
    }
    if take_byte(payload, &mut position)? != 0xcb {
        return Err(CoreError::InvalidField);
    }
    let timestamp = f64::from_bits(read_u64(payload, &mut position)?);
    if !timestamp.is_finite() {
        return Err(CoreError::InvalidField);
    }
    let title = read_binary(payload, &mut position)?;
    let content = read_binary(payload, &mut position)?;
    let fields_start = position;
    if !matches!(
        payload.get(fields_start).copied(),
        Some(0x80..=0x8f | 0xde | 0xdf)
    ) {
        return Err(CoreError::InvalidField);
    }
    skip_value(payload, &mut position, 0)?;
    let fields_end = position;
    let stamp = if length == 5 {
        let stamp = read_binary(payload, &mut position)?;
        if !matches!(stamp.len(), 16 | 32) {
            return Err(CoreError::InvalidField);
        }
        Some(stamp)
    } else {
        None
    };
    if position != payload.len() {
        return Err(CoreError::InvalidField);
    }
    Ok(DecodedPayload {
        timestamp,
        title,
        content,
        fields: payload[fields_start..fields_end].to_vec(),
        stamp,
    })
}

fn read_binary(input: &[u8], position: &mut usize) -> Result<Vec<u8>, CoreError> {
    let marker = take_byte(input, position)?;
    let length = match marker {
        0xc4 => usize::from(take_byte(input, position)?),
        0xc5 => usize::from(read_u16(input, position)?),
        0xc6 => usize::try_from(read_u32(input, position)?).map_err(|_| CoreError::InvalidField)?,
        _ => return Err(CoreError::InvalidField),
    };
    Ok(take(input, position, length)?.to_vec())
}

fn skip_value(input: &[u8], position: &mut usize, depth: u8) -> Result<(), CoreError> {
    if depth >= 64 {
        return Err(CoreError::InvalidField);
    }
    let marker = take_byte(input, position)?;
    match marker {
        0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => {}
        0x80..=0x8f => skip_values(input, position, usize::from(marker & 0x0f) * 2, depth)?,
        0x90..=0x9f => skip_values(input, position, usize::from(marker & 0x0f), depth)?,
        0xa0..=0xbf => {
            take(input, position, usize::from(marker & 0x1f))?;
        }
        0xc4 | 0xd9 => {
            let length = usize::from(take_byte(input, position)?);
            take(input, position, length)?;
        }
        0xc5 | 0xda => {
            let length = usize::from(read_u16(input, position)?);
            take(input, position, length)?;
        }
        0xc6 | 0xdb => {
            let length =
                usize::try_from(read_u32(input, position)?).map_err(|_| CoreError::InvalidField)?;
            take(input, position, length)?;
        }
        0xc7 => {
            let length = usize::from(take_byte(input, position)?);
            take(input, position, length.saturating_add(1))?;
        }
        0xc8 => {
            let length = usize::from(read_u16(input, position)?);
            take(input, position, length.saturating_add(1))?;
        }
        0xc9 => {
            let length =
                usize::try_from(read_u32(input, position)?).map_err(|_| CoreError::InvalidField)?;
            take(
                input,
                position,
                length.checked_add(1).ok_or(CoreError::InvalidField)?,
            )?;
        }
        0xca | 0xce | 0xd2 => {
            take(input, position, 4)?;
        }
        0xcb | 0xcf | 0xd3 => {
            take(input, position, 8)?;
        }
        0xcc | 0xd0 => {
            take(input, position, 1)?;
        }
        0xcd | 0xd1 => {
            take(input, position, 2)?;
        }
        0xd4 => {
            take(input, position, 2)?;
        }
        0xd5 => {
            take(input, position, 3)?;
        }
        0xd6 => {
            take(input, position, 5)?;
        }
        0xd7 => {
            take(input, position, 9)?;
        }
        0xd8 => {
            take(input, position, 17)?;
        }
        0xdc => {
            let count = usize::from(read_u16(input, position)?);
            skip_values(input, position, count, depth)?;
        }
        0xdd => {
            let count =
                usize::try_from(read_u32(input, position)?).map_err(|_| CoreError::InvalidField)?;
            skip_values(input, position, count, depth)?;
        }
        0xde => {
            let count = usize::from(read_u16(input, position)?)
                .checked_mul(2)
                .ok_or(CoreError::InvalidField)?;
            skip_values(input, position, count, depth)?;
        }
        0xdf => {
            let count = usize::try_from(read_u32(input, position)?)
                .map_err(|_| CoreError::InvalidField)?
                .checked_mul(2)
                .ok_or(CoreError::InvalidField)?;
            skip_values(input, position, count, depth)?;
        }
        0xc1 => return Err(CoreError::InvalidField),
    }
    Ok(())
}

fn skip_values(
    input: &[u8],
    position: &mut usize,
    count: usize,
    depth: u8,
) -> Result<(), CoreError> {
    for _ in 0..count {
        skip_value(input, position, depth + 1)?;
    }
    Ok(())
}

fn read_collection_len(
    input: &[u8],
    position: &mut usize,
    fixed_base: u8,
    marker16: u8,
    marker32: u8,
) -> Result<u32, CoreError> {
    let marker = take_byte(input, position)?;
    if marker & 0xf0 == fixed_base {
        Ok(u32::from(marker & 0x0f))
    } else if marker == marker16 {
        Ok(u32::from(read_u16(input, position)?))
    } else if marker == marker32 {
        read_u32(input, position)
    } else {
        Err(CoreError::InvalidField)
    }
}

fn take_byte(input: &[u8], position: &mut usize) -> Result<u8, CoreError> {
    let byte = input.get(*position).copied().ok_or(CoreError::Truncated)?;
    *position += 1;
    Ok(byte)
}

fn take<'a>(input: &'a [u8], position: &mut usize, length: usize) -> Result<&'a [u8], CoreError> {
    let end = position
        .checked_add(length)
        .ok_or(CoreError::InvalidField)?;
    let value = input.get(*position..end).ok_or(CoreError::Truncated)?;
    *position = end;
    Ok(value)
}

fn read_u16(input: &[u8], position: &mut usize) -> Result<u16, CoreError> {
    Ok(u16::from_be_bytes(
        take(input, position, 2)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?,
    ))
}

fn read_u32(input: &[u8], position: &mut usize) -> Result<u32, CoreError> {
    Ok(u32::from_be_bytes(
        take(input, position, 4)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?,
    ))
}

fn read_u64(input: &[u8], position: &mut usize) -> Result<u64, CoreError> {
    Ok(u64::from_be_bytes(
        take(input, position, 8)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?,
    ))
}

fn encode_payload(timestamp: f64, title: &[u8], content: &[u8], fields: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(title.len() + content.len() + fields.len() + 16);
    write_array_len(&mut payload, 4).expect("writing to Vec cannot fail");
    write_f64(&mut payload, timestamp).expect("writing to Vec cannot fail");
    write_bin(&mut payload, title).expect("writing to Vec cannot fail");
    write_bin(&mut payload, content).expect("writing to Vec cannot fail");
    payload.extend_from_slice(fields);
    payload
}

fn hashed_part(
    destination: &[u8; DESTINATION_LENGTH],
    source: &[u8; DESTINATION_LENGTH],
    payload: &[u8],
) -> Vec<u8> {
    let mut hashed = Vec::with_capacity(DESTINATION_LENGTH * 2 + payload.len());
    hashed.extend_from_slice(destination);
    hashed.extend_from_slice(source);
    hashed.extend_from_slice(payload);
    hashed
}

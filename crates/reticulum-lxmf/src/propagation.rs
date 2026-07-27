use alloc::vec::Vec;

use reticulum_core::{
    CoreError, EntropySource,
    destination::{destination_hash, name_hash},
    hash::full_hash,
    identity::{Identity, PublicIdentity},
    token,
};
use rmp::encode::{write_array_len, write_bin, write_f64};

use crate::{LxmfMessage, message::DESTINATION_LENGTH};

const PROPAGATION_ASPECTS: &[&str] = &["propagation"];
const X25519_SECRET_LENGTH: usize = 32;
const TOKEN_IV_LENGTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct PropagationUpload {
    /// Hash of the encrypted LXMF blob before an optional stamp is appended.
    pub transient_id: [u8; 32],
    /// `destination_hash || encrypted_message || optional_stamp`.
    pub lxmf_data: Vec<u8>,
    /// MessagePack `[timestamp, [lxmf_data]]` sent over the propagation link.
    pub packed: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PropagationContainer {
    pub timestamp: f64,
    pub messages: Vec<Vec<u8>>,
}

pub fn propagation_destination_hash(identity: &PublicIdentity) -> [u8; 16] {
    destination_hash(&name_hash("lxmf", PROPAGATION_ASPECTS), &identity.hash())
}

pub fn build_propagation_upload<R: EntropySource>(
    message: &LxmfMessage,
    recipient: &PublicIdentity,
    timestamp: f64,
    stamp: Option<&[u8]>,
    entropy: &mut R,
) -> Result<PropagationUpload, CoreError> {
    if !timestamp.is_finite() {
        return Err(CoreError::InvalidField);
    }
    let mut ephemeral = [0u8; X25519_SECRET_LENGTH];
    let mut iv = [0u8; TOKEN_IV_LENGTH];
    entropy.fill(&mut ephemeral);
    entropy.fill(&mut iv);

    let packed_message = message.pack();
    let encrypted = token::encrypt(
        recipient,
        &packed_message[DESTINATION_LENGTH..],
        &ephemeral,
        &iv,
    );
    let mut unstamped = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
    unstamped.extend_from_slice(&message.destination);
    unstamped.extend_from_slice(&encrypted);
    let transient_id = full_hash(&unstamped);

    let mut lxmf_data = Vec::with_capacity(unstamped.len() + stamp.map_or(0, <[u8]>::len));
    lxmf_data.extend_from_slice(&unstamped);
    if let Some(stamp) = stamp {
        lxmf_data.extend_from_slice(stamp);
    }
    let packed = pack_propagation_container(timestamp, core::slice::from_ref(&lxmf_data));
    Ok(PropagationUpload {
        transient_id,
        lxmf_data,
        packed,
    })
}

pub fn pack_propagation_container(timestamp: f64, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut packed = Vec::new();
    write_array_len(&mut packed, 2).expect("writing to Vec cannot fail");
    write_f64(&mut packed, timestamp).expect("writing to Vec cannot fail");
    write_array_len(
        &mut packed,
        u32::try_from(messages.len()).unwrap_or(u32::MAX),
    )
    .expect("writing to Vec cannot fail");
    for message in messages {
        write_bin(&mut packed, message).expect("writing to Vec cannot fail");
    }
    packed
}

pub fn unpack_propagation_container(bytes: &[u8]) -> Result<PropagationContainer, CoreError> {
    let mut position = 0;
    if read_array_len(bytes, &mut position)? != 2 || take_byte(bytes, &mut position)? != 0xcb {
        return Err(CoreError::InvalidField);
    }
    let timestamp = f64::from_bits(read_u64(bytes, &mut position)?);
    if !timestamp.is_finite() {
        return Err(CoreError::InvalidField);
    }
    let count = read_array_len(bytes, &mut position)?;
    if usize::try_from(count).map_err(|_| CoreError::InvalidField)? > bytes.len() {
        return Err(CoreError::InvalidField);
    }
    let mut messages = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _ in 0..count {
        messages.push(read_binary(bytes, &mut position)?);
    }
    if position != bytes.len() {
        return Err(CoreError::InvalidField);
    }
    Ok(PropagationContainer {
        timestamp,
        messages,
    })
}

/// Decrypt one propagation entry addressed to `recipient`.
///
/// The caller supplies the verified optional stamp length so the stamp can be
/// removed before authenticated token decryption.
pub fn decrypt_propagated_message(
    recipient: &Identity,
    lxmf_data: &[u8],
    stamp_length: usize,
) -> Result<LxmfMessage, CoreError> {
    let encrypted_end = lxmf_data
        .len()
        .checked_sub(stamp_length)
        .ok_or(CoreError::Truncated)?;
    if encrypted_end <= DESTINATION_LENGTH {
        return Err(CoreError::Truncated);
    }
    let destination: [u8; DESTINATION_LENGTH] = lxmf_data[..DESTINATION_LENGTH]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;
    if destination != crate::delivery_destination_hash(&recipient.public()) {
        return Err(CoreError::InvalidField);
    }
    let decrypted = token::decrypt(recipient, &lxmf_data[DESTINATION_LENGTH..encrypted_end])?;
    let mut packed = Vec::with_capacity(DESTINATION_LENGTH + decrypted.len());
    packed.extend_from_slice(&destination);
    packed.extend_from_slice(&decrypted);
    LxmfMessage::unpack(&packed)
}

fn read_array_len(input: &[u8], position: &mut usize) -> Result<u32, CoreError> {
    match take_byte(input, position)? {
        marker @ 0x90..=0x9f => Ok(u32::from(marker & 0x0f)),
        0xdc => Ok(u32::from(read_u16(input, position)?)),
        0xdd => read_u32(input, position),
        _ => Err(CoreError::InvalidField),
    }
}

fn read_binary(input: &[u8], position: &mut usize) -> Result<Vec<u8>, CoreError> {
    let length = match take_byte(input, position)? {
        0xc4 => usize::from(take_byte(input, position)?),
        0xc5 => usize::from(read_u16(input, position)?),
        0xc6 => usize::try_from(read_u32(input, position)?).map_err(|_| CoreError::InvalidField)?,
        _ => return Err(CoreError::InvalidField),
    };
    Ok(take(input, position, length)?.to_vec())
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

fn take_byte(input: &[u8], position: &mut usize) -> Result<u8, CoreError> {
    let byte = *input.get(*position).ok_or(CoreError::Truncated)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn malformed_containers_are_rejected_without_panicking() {
        let valid = pack_propagation_container(42.0, &[vec![1, 2, 3]]);
        for end in 0..valid.len() {
            assert!(unpack_propagation_container(&valid[..end]).is_err());
        }
        assert_eq!(
            unpack_propagation_container(&valid).unwrap().messages,
            [vec![1, 2, 3]]
        );

        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            unpack_propagation_container(&trailing),
            Err(CoreError::InvalidField)
        );
    }
}

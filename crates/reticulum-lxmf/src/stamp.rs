use alloc::{vec, vec::Vec};

use hkdf::Hkdf;
use reticulum_core::{
    CoreError,
    hash::{full_hash, truncated_hash},
};
use sha2::{Digest, Sha256};

pub const STAMP_SIZE: usize = 32;
pub const TICKET_STAMP_SIZE: usize = 16;
pub const DELIVERY_WORKBLOCK_ROUNDS: u32 = 3_000;
pub const PROPAGATION_WORKBLOCK_ROUNDS: u32 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampValidation {
    NotRequired,
    Ticket,
    ProofOfWork { value: u16 },
}

pub fn stamp_workblock(material: &[u8], expand_rounds: u32) -> Result<Vec<u8>, CoreError> {
    if material.is_empty() {
        return Err(CoreError::InvalidField);
    }
    let capacity = usize::try_from(expand_rounds)
        .ok()
        .and_then(|rounds| rounds.checked_mul(256))
        .ok_or(CoreError::InvalidField)?;
    let mut workblock = Vec::with_capacity(capacity);
    let mut block = [0u8; 256];
    for round in 0..expand_rounds {
        let encoded_round = encode_unsigned(u64::from(round));
        let mut salt_material = Vec::with_capacity(material.len() + encoded_round.len());
        salt_material.extend_from_slice(material);
        salt_material.extend_from_slice(&encoded_round);
        let salt = full_hash(&salt_material);
        Hkdf::<Sha256>::new(Some(&salt), material)
            .expand(&[], &mut block)
            .map_err(|_| CoreError::InvalidField)?;
        workblock.extend_from_slice(&block);
    }
    Ok(workblock)
}

pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u16 {
    let digest = hash_joined(workblock, stamp);
    digest
        .iter()
        .map(|byte| byte.leading_zeros() as u16)
        .take_while(|zeros| *zeros == 8)
        .sum::<u16>()
        + digest
            .iter()
            .find(|byte| **byte != 0)
            .map_or(0, |byte| byte.leading_zeros() as u16)
}

pub fn verify_stamp(workblock: &[u8], stamp: &[u8], target_cost: u16) -> bool {
    if stamp.len() != STAMP_SIZE || target_cost > 256 {
        return false;
    }
    if target_cost == 0 {
        return true;
    }
    let digest = hash_joined(workblock, stamp);
    let exponent = 256usize - usize::from(target_cost);
    let mut target = [0u8; 32];
    target[31 - exponent / 8] = 1 << (exponent % 8);
    digest <= target
}

pub fn verify_ticket_stamp(ticket: &[u8], message_id: &[u8; 32], stamp: &[u8]) -> bool {
    if stamp.len() != TICKET_STAMP_SIZE {
        return false;
    }
    let mut material = Vec::with_capacity(ticket.len() + message_id.len());
    material.extend_from_slice(ticket);
    material.extend_from_slice(message_id);
    constant_time_eq(&truncated_hash(&material), stamp)
}

pub fn verify_optional_stamp(
    message_id: &[u8; 32],
    stamp: Option<&[u8]>,
    target_cost: Option<u16>,
    tickets: &[&[u8]],
) -> Result<StampValidation, CoreError> {
    let Some(target_cost) = target_cost.filter(|cost| *cost > 0) else {
        return Ok(StampValidation::NotRequired);
    };
    let stamp = stamp.ok_or(CoreError::InvalidField)?;
    if tickets
        .iter()
        .any(|ticket| verify_ticket_stamp(ticket, message_id, stamp))
    {
        return Ok(StampValidation::Ticket);
    }
    let workblock = stamp_workblock(message_id, DELIVERY_WORKBLOCK_ROUNDS)?;
    if !verify_stamp(&workblock, stamp, target_cost) {
        return Err(CoreError::InvalidField);
    }
    Ok(StampValidation::ProofOfWork {
        value: stamp_value(&workblock, stamp),
    })
}

fn hash_joined(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(first);
    hash.update(second);
    hash.finalize().into()
}

fn encode_unsigned(value: u64) -> Vec<u8> {
    match value {
        0..=0x7f => vec![value as u8],
        0x80..=0xff => vec![0xcc, value as u8],
        0x100..=0xffff => {
            let mut encoded = vec![0xcd];
            encoded.extend_from_slice(&(value as u16).to_be_bytes());
            encoded
        }
        0x1_0000..=0xffff_ffff => {
            let mut encoded = vec![0xce];
            encoded.extend_from_slice(&(value as u32).to_be_bytes());
            encoded
        }
        _ => {
            let mut encoded = vec![0xcf];
            encoded.extend_from_slice(&value.to_be_bytes());
            encoded
        }
    }
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_unstamped_messages_pass_only_without_a_cost() {
        let message_id = [7u8; 32];
        assert_eq!(
            verify_optional_stamp(&message_id, None, None, &[]),
            Ok(StampValidation::NotRequired)
        );
        assert_eq!(
            verify_optional_stamp(&message_id, None, Some(0), &[]),
            Ok(StampValidation::NotRequired)
        );
        assert!(verify_optional_stamp(&message_id, None, Some(1), &[]).is_err());
    }
}

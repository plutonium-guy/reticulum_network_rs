//! RNS Resource wire primitives.
//!
//! The transfer protocol remains available in `no_std + alloc` builds.
//! Optional bz2 payload compression is exposed separately by the
//! `compression` feature; compressed inbound data is unsupported without it.

use alloc::vec::Vec;
use rmp::{
    decode::{read_bin_len, read_int, read_map_len, read_str_len},
    encode::{write_bin, write_map_len, write_nil, write_str, write_uint},
};

use crate::{CoreError, EntropySource, hash::full_hash};

pub const MAPHASH_LEN: usize = 4;
pub const RANDOM_HASH_SIZE: usize = 4;
pub const MAX_EFFICIENT_SIZE: usize = 1024 * 1024 - 1;

pub fn split_parts(data: &[u8], sdu: usize) -> Vec<Vec<u8>> {
    if sdu == 0 {
        return Vec::new();
    }
    data.chunks(sdu).map(<[u8]>::to_vec).collect()
}

pub fn reassemble(parts: &[Vec<u8>]) -> Vec<u8> {
    let capacity = parts.iter().map(Vec::len).sum();
    let mut data = Vec::with_capacity(capacity);
    for part in parts {
        data.extend_from_slice(part);
    }
    data
}

pub fn random_hash<R: EntropySource>(rng: &mut R) -> [u8; RANDOM_HASH_SIZE] {
    let mut source = [0u8; 16];
    rng.fill(&mut source);
    full_hash(&source)[..RANDOM_HASH_SIZE]
        .try_into()
        .unwrap_or([0u8; RANDOM_HASH_SIZE])
}

pub fn resource_hash(data: &[u8], random: &[u8; RANDOM_HASH_SIZE]) -> [u8; 32] {
    hash_joined(data, random)
}

pub fn resource_proof(data: &[u8], hash: &[u8; 32]) -> [u8; 32] {
    hash_joined(data, hash)
}

pub fn map_hash(part: &[u8], random: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
    hash_joined(part, random)[..MAPHASH_LEN]
        .try_into()
        .unwrap_or([0u8; MAPHASH_LEN])
}

pub fn hashmap(parts: &[Vec<u8>], random: &[u8; RANDOM_HASH_SIZE]) -> Vec<u8> {
    let mut map = Vec::with_capacity(parts.len() * MAPHASH_LEN);
    for part in parts {
        map.extend_from_slice(&map_hash(part, random));
    }
    map
}

fn hash_joined(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(left.len() + right.len());
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    full_hash(&input)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAdvertisement {
    pub t: u64,
    pub d: u64,
    pub n: u32,
    pub h: Vec<u8>,
    pub r: Vec<u8>,
    pub o: Vec<u8>,
    pub i: u32,
    pub l: u32,
    pub q: Option<Vec<u8>>,
    pub f: u8,
    pub m: Vec<u8>,
}

impl ResourceAdvertisement {
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = write_map_len(&mut out, 11);
        write_u64_field(&mut out, "t", self.t);
        write_u64_field(&mut out, "d", self.d);
        write_u64_field(&mut out, "n", u64::from(self.n));
        write_bin_field(&mut out, "h", &self.h);
        write_bin_field(&mut out, "r", &self.r);
        write_bin_field(&mut out, "o", &self.o);
        write_u64_field(&mut out, "i", u64::from(self.i));
        write_u64_field(&mut out, "l", u64::from(self.l));
        let _ = write_str(&mut out, "q");
        if let Some(request_id) = &self.q {
            let _ = write_bin(&mut out, request_id);
        } else {
            let _ = write_nil(&mut out);
        }
        write_u64_field(&mut out, "f", u64::from(self.f));
        write_bin_field(&mut out, "m", &self.m);
        out
    }

    pub fn unpack(data: &[u8]) -> Result<Self, CoreError> {
        let mut input = data;
        let fields = read_map_len(&mut input).map_err(|_| CoreError::InvalidField)?;
        if fields != 11 {
            return Err(CoreError::InvalidField);
        }

        let mut t = None;
        let mut d = None;
        let mut n = None;
        let mut h = None;
        let mut r = None;
        let mut o = None;
        let mut i = None;
        let mut l = None;
        let mut q = None;
        let mut f = None;
        let mut m = None;

        for _ in 0..fields {
            let key = read_text(&mut input)?;
            match key {
                "t" => t = Some(read_integer(&mut input)?),
                "d" => d = Some(read_integer(&mut input)?),
                "n" => n = Some(to_u32(read_integer(&mut input)?)?),
                "h" => h = Some(read_binary(&mut input)?),
                "r" => r = Some(read_binary(&mut input)?),
                "o" => o = Some(read_binary(&mut input)?),
                "i" => i = Some(to_u32(read_integer(&mut input)?)?),
                "l" => l = Some(to_u32(read_integer(&mut input)?)?),
                "q" => q = Some(read_optional_binary(&mut input)?),
                "f" => {
                    f = Some(
                        u8::try_from(read_integer(&mut input)?)
                            .map_err(|_| CoreError::InvalidField)?,
                    )
                }
                "m" => m = Some(read_binary(&mut input)?),
                _ => return Err(CoreError::InvalidField),
            }
        }
        if !input.is_empty() {
            return Err(CoreError::InvalidField);
        }
        let advertisement = Self {
            t: t.ok_or(CoreError::InvalidField)?,
            d: d.ok_or(CoreError::InvalidField)?,
            n: n.ok_or(CoreError::InvalidField)?,
            h: h.ok_or(CoreError::InvalidField)?,
            r: r.ok_or(CoreError::InvalidField)?,
            o: o.ok_or(CoreError::InvalidField)?,
            i: i.ok_or(CoreError::InvalidField)?,
            l: l.ok_or(CoreError::InvalidField)?,
            q: q.ok_or(CoreError::InvalidField)?,
            f: f.ok_or(CoreError::InvalidField)?,
            m: m.ok_or(CoreError::InvalidField)?,
        };
        if advertisement.t > (MAX_EFFICIENT_SIZE as u64) * 3
            || advertisement.h.len() != 32
            || advertisement.r.len() != RANDOM_HASH_SIZE
            || advertisement.o.len() != 32
            || !advertisement.m.len().is_multiple_of(MAPHASH_LEN)
            || advertisement.n == 0
        {
            return Err(CoreError::InvalidField);
        }
        Ok(advertisement)
    }

    pub const fn encrypted(&self) -> bool {
        self.f & 0x01 != 0
    }

    pub const fn compressed(&self) -> bool {
        self.f & 0x02 != 0
    }
}

fn write_u64_field(out: &mut Vec<u8>, key: &str, value: u64) {
    let _ = write_str(out, key);
    let _ = write_uint(out, value);
}

fn write_bin_field(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let _ = write_str(out, key);
    let _ = write_bin(out, value);
}

fn read_text<'a>(input: &mut &'a [u8]) -> Result<&'a str, CoreError> {
    let len = usize::try_from(read_str_len(input).map_err(|_| CoreError::InvalidField)?)
        .map_err(|_| CoreError::InvalidField)?;
    let bytes = take(input, len)?;
    core::str::from_utf8(bytes).map_err(|_| CoreError::InvalidField)
}

fn read_binary(input: &mut &[u8]) -> Result<Vec<u8>, CoreError> {
    let len = usize::try_from(read_bin_len(input).map_err(|_| CoreError::InvalidField)?)
        .map_err(|_| CoreError::InvalidField)?;
    Ok(take(input, len)?.to_vec())
}

fn read_optional_binary(input: &mut &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
    if input.first() == Some(&0xC0) {
        *input = &input[1..];
        return Ok(None);
    }
    Ok(Some(read_binary(input)?))
}

fn read_integer(input: &mut &[u8]) -> Result<u64, CoreError> {
    read_int(input).map_err(|_| CoreError::InvalidField)
}

fn to_u32(value: u64) -> Result<u32, CoreError> {
    value.try_into().map_err(|_| CoreError::InvalidField)
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], CoreError> {
    if input.len() < len {
        return Err(CoreError::Truncated);
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

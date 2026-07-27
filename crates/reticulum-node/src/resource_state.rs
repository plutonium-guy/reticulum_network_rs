use alloc::vec::Vec;
use reticulum_core::{
    CoreError, EntropySource,
    resource::{
        MAPHASH_LEN, MAX_EFFICIENT_SIZE, RANDOM_HASH_SIZE, ResourceAdvertisement,
        compress_if_useful, decompress_payload, hashmap, map_hash, pack_hashmap_update,
        random_hash, reassemble, resource_hash, resource_proof, split_parts, unpack_hashmap_update,
    },
    token::{open_with_key, seal_with_key},
};

pub const RESOURCE_SDU: usize = 464;
pub const WINDOW: usize = 4;
pub const WINDOW_MIN: usize = 2;
pub const WINDOW_MAX: usize = 75;
pub const MAX_RETRIES: u8 = 16;
pub const HASHMAP_MAX_LEN: usize = 74;
pub const REQUEST_TIMEOUT_SECS: u64 = 2;
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceOutput {
    Part(Vec<u8>),
    HashmapUpdate(Vec<u8>),
}

#[derive(Debug)]
pub struct OutboundResource {
    pub hash: [u8; 32],
    pub size: u64,
    pub total_size: u64,
    pub parts: Vec<Vec<u8>>,
    pub map: Vec<u8>,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    expected_proof: [u8; 32],
    completed: bool,
    pub last_activity: u64,
}

impl OutboundResource {
    pub fn new<R: EntropySource>(
        data: &[u8],
        link_key: &[u8; 64],
        rng: &mut R,
        now: u64,
    ) -> Result<(Self, Vec<u8>), CoreError> {
        if data.is_empty() || data.len() > MAX_EFFICIENT_SIZE {
            return Err(CoreError::InvalidField);
        }
        let (transmitted, compressed) = compress_if_useful(data);
        let prefix = random_hash(rng);
        let mut stream = Vec::with_capacity(RANDOM_HASH_SIZE + transmitted.len());
        stream.extend_from_slice(&prefix);
        stream.extend_from_slice(&transmitted);
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let encrypted = seal_with_key(link_key, &stream, &iv);
        let parts = split_parts(&encrypted, RESOURCE_SDU);

        let (hash_random, hash, map) = loop {
            let hash_random = random_hash(rng);
            let map = hashmap(&parts, &hash_random);
            let mut hashes: Vec<&[u8]> = Vec::with_capacity(parts.len());
            let mut collision = false;
            for entry in map.chunks_exact(MAPHASH_LEN) {
                if hashes.contains(&entry) {
                    collision = true;
                    break;
                }
                hashes.push(entry);
                if hashes.len() > 2 * WINDOW_MAX + HASHMAP_MAX_LEN {
                    hashes.remove(0);
                }
            }
            if !collision {
                break (hash_random, resource_hash(data, &hash_random), map);
            }
        };
        let expected_proof = resource_proof(data, &hash);
        let advertised_map_len = parts.len().min(HASHMAP_MAX_LEN) * MAPHASH_LEN;
        let advertisement = ResourceAdvertisement {
            t: u64::try_from(encrypted.len()).map_err(|_| CoreError::InvalidField)?,
            d: u64::try_from(data.len()).map_err(|_| CoreError::InvalidField)?,
            n: u32::try_from(parts.len()).map_err(|_| CoreError::InvalidField)?,
            h: hash.to_vec(),
            r: hash_random.to_vec(),
            o: hash.to_vec(),
            i: 1,
            l: 1,
            q: None,
            f: 0x01 | u8::from(compressed) << 1,
            m: map[..advertised_map_len].to_vec(),
        };
        Ok((
            Self {
                hash,
                size: advertisement.t,
                total_size: advertisement.d,
                parts,
                map,
                random_hash: hash_random,
                expected_proof,
                completed: false,
                last_activity: now,
            },
            advertisement.pack(),
        ))
    }

    pub fn on_request(&mut self, request: &[u8], now: u64) -> Vec<ResourceOutput> {
        if request.is_empty() {
            return Vec::new();
        }
        let wants_map = request[0] == HASHMAP_IS_EXHAUSTED;
        let pad = if wants_map { 1 + MAPHASH_LEN } else { 1 };
        if request.len() < pad + 32 || request[pad..pad + 32] != self.hash {
            return Vec::new();
        }
        let requested = &request[pad + 32..];
        if !requested.len().is_multiple_of(MAPHASH_LEN) {
            return Vec::new();
        }
        let mut outputs = Vec::new();
        for requested_hash in requested.chunks_exact(MAPHASH_LEN) {
            if let Some((index, _)) = self
                .map
                .chunks_exact(MAPHASH_LEN)
                .enumerate()
                .find(|(_, hash)| *hash == requested_hash)
            {
                outputs.push(ResourceOutput::Part(self.parts[index].clone()));
            }
        }
        if wants_map {
            let last_hash = &request[1..1 + MAPHASH_LEN];
            if let Some(index) = self
                .map
                .chunks_exact(MAPHASH_LEN)
                .position(|hash| hash == last_hash)
            {
                let segment = (index + 1) / HASHMAP_MAX_LEN;
                if (index + 1).is_multiple_of(HASHMAP_MAX_LEN) {
                    let start = segment * HASHMAP_MAX_LEN * MAPHASH_LEN;
                    let end = ((segment + 1) * HASHMAP_MAX_LEN * MAPHASH_LEN).min(self.map.len());
                    if start < end {
                        outputs.push(ResourceOutput::HashmapUpdate(pack_hashmap_update(
                            &self.hash,
                            u32::try_from(segment).unwrap_or(u32::MAX),
                            &self.map[start..end],
                        )));
                    }
                }
            }
        }
        self.last_activity = now;
        outputs
    }

    pub fn on_proof(&mut self, proof_data: &[u8]) -> bool {
        if proof_data.len() == 64
            && proof_data[..32] == self.hash
            && proof_data[32..] == self.expected_proof
        {
            self.completed = true;
        }
        self.completed
    }
}

#[derive(Debug)]
pub struct InboundResource {
    pub hash: [u8; 32],
    pub size: u64,
    pub total_size: u64,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    compressed: bool,
    map: Vec<Option<[u8; MAPHASH_LEN]>>,
    parts: Vec<Option<Vec<u8>>>,
    outstanding: Vec<[u8; MAPHASH_LEN]>,
    pub window: usize,
    pub retries: u8,
    pub last_request: u64,
    waiting_for_hmu: bool,
}

impl InboundResource {
    pub fn from_advertisement(advertisement: ResourceAdvertisement) -> Result<Self, CoreError> {
        if !advertisement.encrypted()
            || advertisement.h.len() != 32
            || advertisement.r.len() != RANDOM_HASH_SIZE
            || advertisement.n == 0
            || advertisement.n as usize > MAX_EFFICIENT_SIZE / MAPHASH_LEN
        {
            return Err(CoreError::InvalidField);
        }
        let hash = advertisement
            .h
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidField)?;
        let random_hash = advertisement
            .r
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidField)?;
        let count = advertisement.n as usize;
        let mut map = alloc::vec![None; count];
        for (index, entry) in advertisement.m.chunks_exact(MAPHASH_LEN).enumerate() {
            if index >= count {
                return Err(CoreError::InvalidField);
            }
            map[index] = Some(entry.try_into().map_err(|_| CoreError::InvalidField)?);
        }
        Ok(Self {
            hash,
            size: advertisement.t,
            total_size: advertisement.d,
            random_hash,
            compressed: advertisement.compressed(),
            map,
            parts: alloc::vec![None; count],
            outstanding: Vec::new(),
            window: WINDOW,
            retries: 0,
            last_request: 0,
            waiting_for_hmu: false,
        })
    }

    pub fn next_request(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.is_complete() {
            return None;
        }
        let first_missing = self.parts.iter().position(Option::is_none)?;
        let mut request = Vec::new();
        if self.map[first_missing].is_none() {
            let known = self
                .map
                .iter()
                .take(first_missing)
                .rev()
                .flatten()
                .next()
                .copied()?;
            request.push(HASHMAP_IS_EXHAUSTED);
            request.extend_from_slice(&known);
            request.extend_from_slice(&self.hash);
            self.waiting_for_hmu = true;
        } else {
            request.push(HASHMAP_IS_NOT_EXHAUSTED);
            request.extend_from_slice(&self.hash);
            self.outstanding.clear();
            for index in first_missing..(first_missing + self.window).min(self.parts.len()) {
                if self.parts[index].is_none()
                    && let Some(hash) = self.map[index]
                {
                    request.extend_from_slice(&hash);
                    self.outstanding.push(hash);
                }
            }
            if self.outstanding.is_empty() {
                return None;
            }
        }
        self.last_request = now;
        Some(request)
    }

    pub fn on_part(&mut self, part: Vec<u8>) -> bool {
        let hash = map_hash(&part, &self.random_hash);
        let Some(index) = self.map.iter().enumerate().find_map(|(index, expected)| {
            (expected == &Some(hash) && self.parts[index].is_none()).then_some(index)
        }) else {
            return false;
        };
        self.parts[index] = Some(part);
        self.outstanding.retain(|entry| entry != &hash);
        if self.outstanding.is_empty() {
            self.window = (self.window + 1).min(WINDOW_MAX);
            self.retries = 0;
        }
        true
    }

    pub fn on_hashmap_update(&mut self, data: &[u8]) -> Result<(), CoreError> {
        let (hash, segment, update) = unpack_hashmap_update(data)?;
        if hash != self.hash {
            return Err(CoreError::InvalidField);
        }
        let start = usize::try_from(segment)
            .map_err(|_| CoreError::InvalidField)?
            .saturating_mul(HASHMAP_MAX_LEN);
        for (offset, entry) in update.chunks_exact(MAPHASH_LEN).enumerate() {
            let Some(slot) = self.map.get_mut(start + offset) else {
                return Err(CoreError::InvalidField);
            };
            *slot = Some(entry.try_into().map_err(|_| CoreError::InvalidField)?);
        }
        self.waiting_for_hmu = false;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.parts.iter().all(Option::is_some)
    }

    pub fn received_parts(&self) -> usize {
        self.parts.iter().filter(|part| part.is_some()).count()
    }

    pub fn total_parts(&self) -> usize {
        self.parts.len()
    }

    pub fn finalize(&self, link_key: &[u8; 64]) -> Result<Vec<u8>, CoreError> {
        if !self.is_complete() {
            return Err(CoreError::Truncated);
        }
        let parts: Vec<Vec<u8>> = self.parts.iter().flatten().cloned().collect();
        let stream = open_with_key(link_key, &reassemble(&parts))?;
        if stream.len() < RANDOM_HASH_SIZE {
            return Err(CoreError::Truncated);
        }
        let payload = &stream[RANDOM_HASH_SIZE..];
        let data = if self.compressed {
            decompress_payload(payload)?
        } else {
            payload.to_vec()
        };
        if data.len() as u64 != self.total_size
            || resource_hash(&data, &self.random_hash) != self.hash
        {
            return Err(CoreError::DecryptFailed);
        }
        Ok(data)
    }

    pub fn proof_packet(&self, data: &[u8]) -> Vec<u8> {
        let proof = resource_proof(data, &self.hash);
        [self.hash.as_slice(), proof.as_slice()].concat()
    }

    pub fn retry_due(&mut self, now: u64) -> Result<Option<Vec<u8>>, CoreError> {
        if self.last_request == 0
            || now.saturating_sub(self.last_request) < REQUEST_TIMEOUT_SECS
            || self.is_complete()
        {
            return Ok(None);
        }
        if self.retries >= MAX_RETRIES {
            return Err(CoreError::Unsupported);
        }
        self.retries += 1;
        self.window = self.window.saturating_sub(1).max(WINDOW_MIN);
        Ok(self.next_request(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    #[test]
    fn outbound_and_inbound_resource_roundtrip_with_retry() {
        let data = alloc::vec![0x5A; 8 * 1024];
        let key = [0x31; 64];
        let mut rng = SeededRng::new(44);
        let (mut outbound, advertisement) =
            OutboundResource::new(&data, &key, &mut rng, 1).unwrap();
        let advertisement = ResourceAdvertisement::unpack(&advertisement).unwrap();
        let mut inbound = InboundResource::from_advertisement(advertisement).unwrap();

        let first_request = inbound.next_request(1).unwrap();
        assert!(inbound.retry_due(2).unwrap().is_none());
        let retry = inbound.retry_due(3).unwrap().unwrap();
        assert_eq!(&retry[..33], &first_request[..33]);
        assert!(retry.len() <= first_request.len());
        assert_eq!(inbound.window, WINDOW_MIN.max(WINDOW - 1));

        while !inbound.is_complete() {
            let request = inbound.next_request(4).unwrap();
            for output in outbound.on_request(&request, 4) {
                match output {
                    ResourceOutput::Part(part) => assert!(inbound.on_part(part)),
                    ResourceOutput::HashmapUpdate(update) => {
                        inbound.on_hashmap_update(&update).unwrap()
                    }
                }
            }
        }
        let received = inbound.finalize(&key).unwrap();
        assert_eq!(received, data);
        let proof = inbound.proof_packet(&received);
        assert!(outbound.on_proof(&proof));
    }

    #[test]
    fn corrupted_resource_part_is_rejected() {
        let key = [0x41; 64];
        let mut rng = SeededRng::new(55);
        let (mut outbound, advertisement) =
            OutboundResource::new(&alloc::vec![7; 2048], &key, &mut rng, 1).unwrap();
        let mut inbound = InboundResource::from_advertisement(
            ResourceAdvertisement::unpack(&advertisement).unwrap(),
        )
        .unwrap();
        let request = inbound.next_request(1).unwrap();
        let mut part = match outbound.on_request(&request, 1).remove(0) {
            ResourceOutput::Part(part) => part,
            ResourceOutput::HashmapUpdate(_) => unreachable!(),
        };
        part[0] ^= 1;
        assert!(!inbound.on_part(part));
    }
}

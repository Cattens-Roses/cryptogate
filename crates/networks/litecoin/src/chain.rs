//! Mainnet header consensus: SHA256d block IDs, Scrypt PoW, Litecoin retargets.
use crate::header_cache;
use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    block::{Header, Version},
    consensus::{deserialize, serialize},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wallet_core::vault::atomic_write;
use zeroize::Zeroizing;

pub const INTERVAL: usize = 2016;
const TIMESPAN: i64 = 302_400;

pub fn genesis() -> Header {
    Header {
        version: Version::from_consensus(1),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::from_str(
            "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9",
        )
        .expect("constant"),
        time: 1_317_972_665,
        bits: CompactTarget::from_consensus(0x1e0ffff0),
        nonce: 2_084_524_493,
    }
}

fn pow_limit() -> BigUint {
    (BigUint::one() << 236usize) - BigUint::one()
}

pub fn target(bits: u32) -> Result<BigUint> {
    let size = bits >> 24;
    let word = bits & 0x007fffff;
    ensure!(
        word > 0 && bits & 0x00800000 == 0 && size <= 32,
        "Invalid compact target"
    );
    let value = if size <= 3 {
        BigUint::from(word >> (8 * (3 - size)))
    } else {
        BigUint::from(word) << (8 * (size - 3)) as usize
    };
    ensure!(
        !value.is_zero() && value <= pow_limit(),
        "Target exceeds Litecoin PoW limit"
    );
    Ok(value)
}

fn compact(value: &BigUint) -> u32 {
    let mut bytes = value.to_bytes_be();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    let size = bytes.len() as u32;
    let mut word = 0u32;
    for i in 0..3 {
        word = (word << 8) | u32::from(*bytes.get(i).unwrap_or(&0));
    }
    (size << 24) | word
}

pub fn verify_pow(header: &Header) -> Result<()> {
    let threshold = target(header.bits.to_consensus())?;
    let raw = serialize(header);
    let mut hash = [0u8; 32];
    // Litecoin's PoW uses the header as both password and salt, N=1024/r=1/p=1.
    scrypt::scrypt(
        &raw,
        &raw,
        &scrypt::Params::new(10, 1, 1).expect("constant Scrypt parameters"),
        &mut hash,
    )
    .map_err(|e| anyhow::anyhow!("Scrypt failed: {e}"))?;
    ensure!(
        BigUint::from_bytes_le(&hash) <= threshold,
        "Invalid Litecoin Scrypt proof of work"
    );
    Ok(())
}

fn work(header: &Header) -> BigUint {
    (BigUint::one() << 256usize)
        / (target(header.bits.to_consensus()).expect("validated target") + BigUint::one())
}

fn next_bits(height: usize, get: impl Fn(usize) -> Header) -> Result<u32> {
    let previous = get(height - 1);
    if !height.is_multiple_of(INTERVAL) {
        return Ok(previous.bits.to_consensus());
    }
    let first = if height == INTERVAL {
        0
    } else {
        height - INTERVAL - 1
    };
    let elapsed =
        (i64::from(previous.time) - i64::from(get(first).time)).clamp(TIMESPAN / 4, TIMESPAN * 4);
    let mut next = target(previous.bits.to_consensus())?;
    // Match Litecoin Core's historical intermediate shift before multiplication.
    let shift = next.bits() > pow_limit().bits() - 1;
    if shift {
        next >>= 1usize;
    }
    next = next * BigUint::from(elapsed as u64) / BigUint::from(TIMESPAN as u64);
    if shift {
        next <<= 1usize;
    }
    Ok(compact(&next.min(pow_limit())))
}

fn validate_pow_batch(
    headers: &[Header],
    base: usize,
    cancel: &AtomicBool,
    workers: usize,
) -> Result<()> {
    let chunk_size = headers.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| -> Result<()> {
        let handles: Vec<_> = headers
            .chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                scope.spawn(move || -> Result<()> {
                    for (index, header) in chunk.iter().enumerate() {
                        ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
                        verify_pow(header).with_context(|| {
                            format!(
                                "Invalid cached header at height {}",
                                base + chunk_index * chunk_size + index
                            )
                        })?;
                    }
                    Ok(())
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("Header validation worker panicked"))??;
        }
        Ok(())
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheLoadStats {
    pub authenticated_headers: u32,
    pub validated_headers: u32,
}

pub struct HeaderChain {
    headers: Vec<Header>,
    chain_work: BigUint,
    path: PathBuf,
    candidate: Option<(usize, Vec<Header>)>,
    cache_key: Option<Zeroizing<[u8; 32]>>,
    cache_digest: Sha256,
    load_stats: CacheLoadStats,
}

impl HeaderChain {
    pub fn open(path: &Path, cancel: &AtomicBool) -> Result<Self> {
        Self::open_inner(path, None, cancel, &|_| {})
    }

    /// Resume only an exact, wallet-authenticated prefix; fully validate every new header.
    pub fn open_authenticated(
        path: &Path,
        seed: &[u8; 64],
        cancel: &AtomicBool,
        progress: &dyn Fn(&str),
    ) -> Result<Self> {
        Self::open_inner(path, Some(header_cache::derive_key(seed)), cancel, progress)
    }

    fn open_inner(
        path: &Path,
        cache_key: Option<Zeroizing<[u8; 32]>>,
        cancel: &AtomicBool,
        progress: &dyn Fn(&str),
    ) -> Result<Self> {
        let mut chain = Self {
            headers: vec![genesis()],
            chain_work: work(&genesis()),
            path: path.to_owned(),
            candidate: None,
            cache_key,
            cache_digest: Sha256::new(),
            load_stats: CacheLoadStats::default(),
        };
        if !path.exists() {
            return Ok(chain);
        }
        progress("Checking cached header integrity…");
        let bytes = fs::read(path)?;
        ensure!(
            bytes.len() / 80 < u32::MAX as usize,
            "Header cache is too large"
        );
        let complete_bytes = bytes.len() / 80 * 80;
        let total = complete_bytes / 80;
        let prefix = chain
            .cache_key
            .as_ref()
            .and_then(|key| header_cache::read(&path.with_extension("verified.json"), key, total));
        if let Some(prefix) = prefix {
            let prefix_len = prefix.height as usize * 80;
            let mut digest = Sha256::new();
            for chunk in bytes[..prefix_len].chunks(1024 * 1024) {
                ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
                digest.update(chunk);
            }
            let hash: [u8; 32] = digest.clone().finalize().into();
            let tip = if prefix.height == 0 {
                genesis()
            } else {
                deserialize::<Header>(&bytes[prefix_len - 80..prefix_len])?
            };
            if hash == prefix.headers_hash && tip.block_hash() == prefix.tip {
                for raw in bytes[..prefix_len].chunks_exact(80) {
                    ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
                    chain.headers.push(deserialize(raw)?);
                }
                chain.chain_work = prefix.work;
                chain.cache_digest = digest;
                chain.load_stats.authenticated_headers = prefix.height;
                progress(&format!(
                    "Authenticated {} cached headers · Scrypt checks reused",
                    prefix.height
                ));
            } else {
                progress("Header cache changed · validating consensus again…");
            }
        }

        let start = chain.height() as usize * 80;
        let started = Instant::now();
        let workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(8);
        if start < complete_bytes {
            progress(&format!(
                "Validating cached headers: {}/{total} · {workers} workers",
                chain.height()
            ));
        }
        for raw_batch in bytes[start..complete_bytes].chunks(2000 * 80) {
            ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
            let headers: Vec<Header> = raw_batch
                .chunks_exact(80)
                .map(deserialize)
                .collect::<std::result::Result<_, _>>()?;
            let base = chain.headers.len();
            for (index, header) in headers.iter().enumerate() {
                chain.validate_rules(header, base, &headers[..index])?;
            }
            validate_pow_batch(&headers, base, cancel, workers)?;
            chain.chain_work += headers.iter().map(work).sum::<BigUint>();
            chain.headers.extend_from_slice(&headers);
            chain.cache_digest.update(raw_batch);
            chain.load_stats.validated_headers += headers.len() as u32;
            // Save every batch so an interrupted migration never starts over at genesis.
            chain.save_checkpoint()?;
            let rate = chain.load_stats.validated_headers as f64
                / started.elapsed().as_secs_f64().max(0.001);
            progress(&format!(
                "Validating cached headers: {}/{total} · {rate:.0} headers/s",
                chain.height()
            ));
        }
        // An interrupted append can leave a partial final header, never a committed header.
        if bytes.len() % 80 != 0 {
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len((bytes.len() / 80 * 80) as u64)?;
            file.sync_all()?;
        }
        progress(&format!(
            "Header cache ready · {} reused, {} newly validated",
            chain.load_stats.authenticated_headers, chain.load_stats.validated_headers
        ));
        Ok(chain)
    }

    pub fn cache_load_stats(&self) -> CacheLoadStats {
        self.load_stats
    }

    fn save_checkpoint(&self) -> Result<()> {
        if let Some(key) = &self.cache_key {
            header_cache::write(
                &self.path.with_extension("verified.json"),
                key,
                self.height(),
                self.hash(self.height()).expect("tip"),
                &self.chain_work,
                self.cache_digest.clone().finalize().into(),
            )?;
        }
        Ok(())
    }

    pub fn height(&self) -> u32 {
        self.headers.len() as u32 - 1
    }

    /// A historical Litecoin Core minimum-work floor, not an estimate of today's tip.
    pub fn has_minimum_work(&self) -> bool {
        self.chain_work >= BigUint::parse_bytes(b"146878abee06fa883e0a", 16).expect("constant work")
    }
    pub fn header(&self, height: u32) -> Option<Header> {
        self.headers.get(height as usize).copied()
    }
    pub fn hash(&self, height: u32) -> Option<BlockHash> {
        self.header(height).map(|h| h.block_hash())
    }

    pub fn locator(&self) -> Vec<BlockHash> {
        let (base, candidate) = self
            .candidate
            .as_ref()
            .map(|(base, headers)| (*base, headers.as_slice()))
            .unwrap_or((self.headers.len(), &[]));
        let mut height = (base + candidate.len() - 1) as u32;
        let mut step = 1;
        let mut result = Vec::new();
        loop {
            let header = if (height as usize) < base {
                self.headers[height as usize]
            } else {
                candidate[height as usize - base]
            };
            result.push(header.block_hash());
            if height == 0 {
                break;
            }
            if result.len() > 10 {
                step *= 2;
            }
            height = height.saturating_sub(step);
        }
        result
    }

    pub fn has_candidate(&self) -> bool {
        self.candidate.is_some()
    }
    pub fn discard_candidate(&mut self) {
        self.candidate = None;
    }

    fn validate_rules(&self, header: &Header, base: usize, extra: &[Header]) -> Result<()> {
        let height = base + extra.len();
        let get = |i: usize| {
            if i < base {
                self.headers[i]
            } else {
                extra[i - base]
            }
        };
        ensure!(
            header.prev_blockhash == get(height - 1).block_hash(),
            "Broken header link"
        );
        ensure!(
            header.bits.to_consensus() == next_bits(height, get)?,
            "Unexpected Litecoin difficulty at height {height}"
        );
        let mut times: Vec<u32> = (height.saturating_sub(11)..height)
            .map(|i| get(i).time)
            .collect();
        times.sort_unstable();
        ensure!(
            header.time > times[times.len() / 2],
            "Header fails median-time-past"
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            u64::from(header.time) <= now + 7200,
            "Header timestamp too far in future"
        );
        let checkpoint = match height {
            1500 => Some("841a2965955dd288cfa707a755d05a54e45f8bd476835ec9af4402a2b59a2967"),
            4032 => Some("9ce90e427198fc0ef05e5905ce3503725b80e26afd35a987965fd7e3d9cf0846"),
            721000 => Some("198a7b4de1df9478e2463bd99d75b714eab235a2e63e741641dc8a759a9840e5"),
            _ => None,
        };
        if let Some(expected) = checkpoint {
            ensure!(
                header.block_hash().to_string() == expected,
                "Litecoin checkpoint mismatch at {height}"
            );
        }
        Ok(())
    }

    /// Validate the entire batch before changing memory or disk; select strictly greater work.
    /// Returns the common ancestor, allowing the wallet to invalidate orphaned proofs.
    pub fn apply(&mut self, incoming: &[Header], cancel: &AtomicBool) -> Result<u32> {
        ensure!(incoming.len() <= 2000, "Oversized headers response");
        if incoming.is_empty() {
            ensure!(
                self.candidate.is_none(),
                "Peer ended a fork before it exceeded current chain work"
            );
            return Ok(self.height());
        }
        let continuing = self.candidate.as_ref().is_some_and(|(_, headers)| {
            headers
                .last()
                .is_some_and(|h| h.block_hash() == incoming[0].prev_blockhash)
        });
        let (base, mut candidate) = if continuing {
            self.candidate.as_ref().expect("checked candidate").clone()
        } else {
            let ancestor = if self.headers.last().expect("genesis").block_hash()
                == incoming[0].prev_blockhash
            {
                self.headers.len() - 1
            } else {
                self.headers
                    .iter()
                    .rposition(|h| h.block_hash() == incoming[0].prev_blockhash)
                    .context("Peer supplied an unknown fork ancestor")?
            };
            (ancestor + 1, Vec::new())
        };
        let incoming_base = base + candidate.len();
        for header in incoming {
            if cancel.load(Ordering::Relaxed) {
                bail!("Cancelled");
            }
            self.validate_rules(header, base, &candidate)?;
            candidate.push(*header);
        }
        let workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(8);
        validate_pow_batch(incoming, incoming_base, cancel, workers)?;
        let removed: BigUint = self.headers[base..].iter().map(work).sum();
        let added: BigUint = candidate.iter().map(work).sum();
        if added <= removed {
            // Continue fetching this fork across message boundaries without touching the
            // active chain or its wallet until the candidate has strictly greater work.
            self.candidate = Some((base, candidate));
            return Ok(self.height());
        }
        let mut bytes = Vec::with_capacity(candidate.len() * 80);
        for header in &candidate {
            bytes.extend(serialize(header));
        }
        let mut digest = self.cache_digest.clone();
        if base == self.headers.len() {
            let expected = (self.headers.len() as u64 - 1) * 80;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&self.path)?;
            ensure!(
                file.metadata()?.len() >= expected,
                "Header cache was truncated while open"
            );
            file.set_len(expected)?;
            file.seek(SeekFrom::Start(expected))?;
            if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
                let _ = file.set_len(expected);
                let _ = file.sync_all();
                return Err(error.into());
            }
            digest.update(&bytes);
        } else {
            let mut replacement = Vec::with_capacity((base - 1) * 80 + bytes.len());
            for header in &self.headers[1..base] {
                replacement.extend(serialize(header));
            }
            replacement.extend(bytes);
            atomic_write(&self.path, &replacement)?;
            digest = Sha256::new();
            digest.update(&replacement);
        }
        self.headers.truncate(base);
        self.headers.extend_from_slice(&candidate);
        self.chain_work = &self.chain_work - removed + added;
        self.candidate = None;
        self.cache_digest = digest;
        self.save_checkpoint()?;
        Ok(base as u32 - 1)
    }

    #[cfg(test)]
    pub(crate) fn signing_test_chain(&mut self) {
        // Only compiled into unit tests. Funding/signing tests do not mine Scrypt blocks.
        while self.headers.len() <= 6 {
            let mut header = *self.headers.last().unwrap();
            header.prev_blockhash = header.block_hash();
            header.time += 150;
            self.headers.push(header);
        }
        self.chain_work = BigUint::one() << 128usize;
    }

    #[cfg(test)]
    pub(crate) fn proof_test_chain(&mut self, header: Header) {
        // Isolate proof/discovery tests from mining; production always verifies Scrypt.
        self.headers = vec![genesis(), header];
        self.chain_work = BigUint::one() << 128usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn litecoin_genesis_scrypt_and_block_id() {
        let header = genesis();
        assert_eq!(
            header.block_hash().to_string(),
            "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
        );
        verify_pow(&header).unwrap();
        let mut bad = header;
        bad.nonce += 1;
        assert!(verify_pow(&bad).is_err());
        for bits in [0, 0x1e8ffff0, 0x2100ffff, 0x1f00ffff] {
            assert!(target(bits).is_err());
        }
        assert_eq!(compact(&target(0x1e0ffff0).unwrap()), 0x1e0ffff0);
    }
    #[test]
    fn invalid_batch_does_not_change_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&path, &cancel).unwrap();
        let mut fake = genesis();
        fake.prev_blockhash = genesis().block_hash();
        fake.time += 1;
        assert!(chain.apply(&[fake], &cancel).is_err());
        assert_eq!(chain.height(), 0);
        assert!(!path.exists());
        assert_eq!(chain.locator(), vec![genesis().block_hash()]);
    }
    #[test]
    fn litecoin_retarget_uses_full_period_after_first() {
        let mut headers = vec![genesis(); 4032];
        for (i, h) in headers.iter_mut().enumerate() {
            h.time += i as u32 * 150;
        }
        let first = next_bits(2016, |i| headers[i]).unwrap();
        let second = next_bits(4032, |i| headers[i]).unwrap();
        assert_ne!(first, genesis().bits.to_consensus());
        assert_eq!(second, genesis().bits.to_consensus());
    }

    #[test]
    fn actual_litecoin_headers_persist_and_partial_append_recovers() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let headers: Vec<Header> = fixture[..80 * 8]
            .chunks_exact(80)
            .map(|raw| deserialize(raw).unwrap())
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&path, &cancel).unwrap();
        chain.apply(&headers, &cancel).unwrap();
        assert_eq!(chain.height(), 8);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[42; 7])
            .unwrap();
        let reopened = HeaderChain::open(&path, &cancel).unwrap();
        assert_eq!(reopened.hash(8), chain.hash(8));
        assert_eq!(fs::metadata(path).unwrap().len(), 80 * 8);
    }

    #[test]
    fn candidate_chain_spans_batches_and_commits_only_after_more_work() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let headers: Vec<Header> = fixture[..80 * 9]
            .chunks_exact(80)
            .map(|raw| deserialize(raw).unwrap())
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&path, &cancel).unwrap();
        chain.apply(&headers[..8], &cancel).unwrap();
        assert_eq!(chain.apply(&headers[..4], &cancel).unwrap(), 8);
        assert!(chain.has_candidate());
        assert_eq!(chain.height(), 8);
        assert_eq!(fs::metadata(&path).unwrap().len(), 640);
        assert_eq!(chain.locator()[0], headers[3].block_hash());
        assert_eq!(chain.apply(&headers[4..], &cancel).unwrap(), 0);
        assert!(!chain.has_candidate());
        assert_eq!(chain.height(), 9);
        assert_eq!(
            HeaderChain::open(&path, &cancel).unwrap().hash(9),
            Some(headers[8].block_hash())
        );
    }

    #[test]
    fn authenticated_cache_reuses_pow_and_validates_only_an_unsealed_tail() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let cancel = AtomicBool::new(false);
        let seed = [17; 64];
        fs::write(&path, &fixture[..80 * 8]).unwrap();
        let first = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(first.cache_load_stats().validated_headers, 8);
        let second = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(second.cache_load_stats().authenticated_headers, 8);
        assert_eq!(second.cache_load_stats().validated_headers, 0);
        assert_eq!(first.chain_work, second.chain_work);
        // Simulate an append committed just before its receipt was persisted.
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&fixture[80 * 8..80 * 9])
            .unwrap();
        let resumed = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(resumed.cache_load_stats().authenticated_headers, 8);
        assert_eq!(resumed.cache_load_stats().validated_headers, 1);
        let header: Header = deserialize(&fixture[80 * 9..80 * 10]).unwrap();
        let mut resumed = resumed;
        resumed.apply(&[header], &cancel).unwrap();
        let warm = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(warm.cache_load_stats().authenticated_headers, 10);
        assert_eq!(warm.cache_load_stats().validated_headers, 0);
    }

    #[test]
    fn modified_headers_or_receipts_cannot_skip_validation() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let receipt_path = path.with_extension("verified.json");
        let cancel = AtomicBool::new(false);
        let seed = [18; 64];
        fs::write(&path, &fixture[..80 * 8]).unwrap();
        HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        receipt["checkpoint"]["work"] =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let rechecked = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(rechecked.cache_load_stats().authenticated_headers, 0);
        assert_eq!(rechecked.cache_load_stats().validated_headers, 8);
        assert!(!rechecked.has_minimum_work());
        let differently_keyed =
            HeaderChain::open_authenticated(&path, &[19; 64], &cancel, &|_| {}).unwrap();
        assert_eq!(differently_keyed.cache_load_stats().validated_headers, 8);
        let mut damaged = fixture[..80 * 8].to_vec();
        damaged[76] ^= 1;
        fs::write(&path, damaged).unwrap();
        assert!(HeaderChain::open_authenticated(&path, &[19; 64], &cancel, &|_| {}).is_err());
    }

    #[test]
    fn authenticated_receipt_is_rebuilt_after_chain_replacement() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        let cancel = AtomicBool::new(false);
        let seed = [20; 64];
        let headers: Vec<Header> = fixture[..80 * 9]
            .chunks_exact(80)
            .map(|raw| deserialize(raw).unwrap())
            .collect();
        let mut chain = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        chain.apply(&headers[..8], &cancel).unwrap();
        chain.apply(&headers[..4], &cancel).unwrap();
        chain.apply(&headers[4..], &cancel).unwrap();
        let restored = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(restored.cache_load_stats().authenticated_headers, 9);
        assert_eq!(restored.cache_load_stats().validated_headers, 0);
        assert_eq!(restored.chain_work, chain.chain_work);
    }

    #[test]
    #[ignore = "full migration regression; run with --release -- --include-ignored"]
    fn interrupted_migration_resumes_at_last_authenticated_batch() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        fs::write(&path, fixture).unwrap();
        let cancel = AtomicBool::new(false);
        let seed = [21; 64];
        let result = HeaderChain::open_authenticated(&path, &seed, &cancel, &|message| {
            if message.starts_with("Validating cached headers: 2000/") {
                cancel.store(true, Ordering::Relaxed);
            }
        });
        assert!(result.is_err());
        cancel.store(false, Ordering::Relaxed);
        let resumed = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {}).unwrap();
        assert_eq!(resumed.cache_load_stats().authenticated_headers, 2000);
        assert_eq!(resumed.cache_load_stats().validated_headers, 2032);
    }

    #[test]
    #[ignore = "Scrypt validation of 4032 real headers; run with --release -- --ignored"]
    fn historical_chain_crosses_both_litecoin_retarget_boundaries() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.dat");
        fs::write(&path, fixture).unwrap();
        let chain = HeaderChain::open(&path, &AtomicBool::new(false)).unwrap();
        assert_eq!(chain.height(), 4032);
        assert_eq!(
            chain.hash(4032).unwrap().to_string(),
            "9ce90e427198fc0ef05e5905ce3503725b80e26afd35a987965fd7e3d9cf0846"
        );
    }
}

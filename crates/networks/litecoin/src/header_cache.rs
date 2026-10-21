//! Wallet-keyed receipts attest which exact bytes have passed header consensus.
//! Bump FORMAT when changing cached-header consensus rules.
use anyhow::{Context, Result};
use bitcoin::BlockHash;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs, path::Path};
use wallet_core::vault::atomic_write;
use zeroize::Zeroizing;

const FORMAT: u32 = 1;
const DOMAIN: &[u8] = b"enginecore/litecoin-mainnet/verified-headers/v1";
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    height: u32,
    tip: BlockHash,
    work: String,
    headers_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    checkpoint: Checkpoint,
    tag: [u8; 32],
}

pub(crate) struct VerifiedPrefix {
    pub height: u32,
    pub tip: BlockHash,
    pub work: BigUint,
    pub headers_hash: [u8; 32],
}

pub(crate) fn derive_key(seed: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(DOMAIN);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn authenticator(key: &[u8; 32], checkpoint: &Checkpoint) -> Result<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(DOMAIN);
    mac.update(&serde_json::to_vec(checkpoint)?);
    Ok(mac)
}

pub(crate) fn read(
    path: &Path,
    key: &[u8; 32],
    available_headers: usize,
) -> Option<VerifiedPrefix> {
    let read = || -> Result<Option<VerifiedPrefix>> {
        if !path.exists() || fs::metadata(path)?.len() > 4096 {
            return Ok(None);
        }
        let receipt: Receipt = serde_json::from_slice(&fs::read(path)?)?;
        let checkpoint = receipt.checkpoint;
        if checkpoint.version != FORMAT
            || checkpoint.height as usize > available_headers
            || checkpoint.work.len() > 80
        {
            return Ok(None);
        }
        // verify_slice compares authentication tags in constant time.
        if authenticator(key, &checkpoint)?
            .verify_slice(&receipt.tag)
            .is_err()
        {
            return Ok(None);
        }
        let work = BigUint::parse_bytes(checkpoint.work.as_bytes(), 16)
            .context("Invalid cached chain work")?;
        Ok(Some(VerifiedPrefix {
            height: checkpoint.height,
            tip: checkpoint.tip,
            work,
            headers_hash: checkpoint.headers_hash,
        }))
    };
    // Missing, old, damaged, or differently keyed receipts never bypass validation.
    read().ok().flatten()
}

pub(crate) fn write(
    path: &Path,
    key: &[u8; 32],
    height: u32,
    tip: BlockHash,
    work: &BigUint,
    headers_hash: [u8; 32],
) -> Result<()> {
    let checkpoint = Checkpoint {
        version: FORMAT,
        height,
        tip,
        work: work.to_str_radix(16),
        headers_hash,
    };
    let tag = authenticator(key, &checkpoint)?
        .finalize()
        .into_bytes()
        .into();
    atomic_write(path, &serde_json::to_vec(&Receipt { checkpoint, tag })?)
        .context("Save verified-header checkpoint")
}

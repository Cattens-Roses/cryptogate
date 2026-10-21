use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use bip39::Mnemonic;
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
};
use zeroize::Zeroizing;

const AAD: &[u8] = b"enginecore/vault/v1";

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct Vault {
    seed: Zeroizing<[u8; 64]>,
    _lock: File,
}

impl Vault {
    /// Mnemonic is shown once; it is never stored unencrypted.
    pub fn create(
        dir: &Path,
        password: &str,
        import: Option<&str>,
    ) -> Result<(Self, Zeroizing<String>)> {
        if password.chars().count() < 10 {
            bail!("Use a password of at least 10 characters");
        }
        fs::create_dir_all(dir)?;
        let lock = lock(dir)?;
        let path = dir.join("vault.json");
        if path.exists() {
            bail!("A wallet already exists in {}", dir.display());
        }
        let mnemonic = match import {
            Some(words) => Mnemonic::parse(words).context("Invalid BIP39 mnemonic")?,
            None => Mnemonic::generate_in_with(&mut OsRng, bip39::Language::English, 24)?,
        };
        let words = Zeroizing::new(mnemonic.to_string());
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("Cipher initialization failed"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: words.as_bytes(),
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow!("Encryption failed"))?;
        let envelope = Envelope {
            version: 1,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        // Exclusive creation prevents accidental replacement, including concurrent creation.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&serde_json::to_vec_pretty(&envelope)?)?;
        file.sync_all()?;
        Ok((Self { seed, _lock: lock }, words))
    }

    pub fn open(dir: &Path, password: &str) -> Result<Self> {
        let lock = lock(dir)?;
        let path = dir.join("vault.json");
        if fs::metadata(&path)?.len() > 16_384 {
            bail!("Vault file is too large");
        }
        let envelope: Envelope = serde_json::from_slice(&fs::read(path)?)?;
        if envelope.version != 1 {
            bail!("Unsupported vault format");
        }
        let salt = hex::decode(envelope.salt)?;
        let nonce = hex::decode(envelope.nonce)?;
        if salt.len() != 16 || nonce.len() != 12 {
            bail!("Invalid vault parameters");
        }
        let key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("Cipher initialization failed"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &hex::decode(envelope.ciphertext)?,
                        aad: AAD,
                    },
                )
                .map_err(|_| anyhow!("Wrong password or damaged vault"))?,
        );
        let mnemonic = Mnemonic::parse(std::str::from_utf8(&plaintext)?)?;
        Ok(Self {
            seed: Zeroizing::new(mnemonic.to_seed("")),
            _lock: lock,
        })
    }

    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    // Argon2id v19: 19 MiB, 2 iterations, 1 lane; fixed in vault version 1.
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("Password KDF failed: {e}"))?;
    Ok(key)
}

fn lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("wallet.lock"))?;
    file.try_lock_exclusive()
        .context("Wallet is already open in another process")?;
    Ok(file)
}

/// Crash-safe replacement on Unix and Windows, on the destination filesystem.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing parent directory")?;
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".{}.tmp", hex::encode(random)));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .context("Create temporary state file")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path).context("Atomically replace state file")?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vault_roundtrip_lock_password_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, words) = Vault::create(dir.path(), "a long test password", None).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let seed = *vault.seed();
        assert!(Vault::open(dir.path(), "a long test password").is_err());
        drop(vault);
        assert!(Vault::open(dir.path(), "wrong password").is_err());
        let reopened = Vault::open(dir.path(), "a long test password").unwrap();
        assert_eq!(*reopened.seed(), seed);
        drop(reopened);
        assert!(Vault::create(dir.path(), "a long test password", None).is_err());
        let path = dir.path().join("vault.json");
        let mut envelope: Envelope = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut ciphertext = hex::decode(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        envelope.ciphertext = hex::encode(ciphertext);
        fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(Vault::open(dir.path(), "a long test password").is_err());
    }
}

use anyhow::{ensure, Result};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::Secp256k1,
};
use myotis_core::{keccak::keccak256, nodekey::NodeKey};
use zeroize::Zeroizing;

pub fn derive(master: &Xpriv, index: u32) -> Result<NodeKey> {
    ensure!(index < 1 << 31, "Ethereum address index exhausted");
    let path: DerivationPath = format!("m/44'/60'/0'/0/{index}").parse()?;
    let child = master.derive_priv(&Secp256k1::new(), &path)?;
    let secret = Zeroizing::new(child.private_key.secret_bytes());
    NodeKey::from_secret_bytes(&secret).map_err(|error| anyhow::anyhow!(error.0))
}

pub fn from_key(key: &NodeKey) -> [u8; 20] {
    keccak256(&key.public_key_bytes())[12..]
        .try_into()
        .expect("20 bytes")
}

pub fn checksum(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut text = String::from("0x");
    for (byte, nibble) in lower.bytes().zip(hash.bytes()) {
        text.push(if nibble >= b'8' {
            byte.to_ascii_uppercase()
        } else {
            byte
        } as char);
    }
    text
}

pub fn parse(text: &str) -> Result<[u8; 20]> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Use a 0x Ethereum mainnet address"))?;
    ensure!(
        body.len() == 40 && body.bytes().all(|b| b.is_ascii_hexdigit()),
        "Ethereum address must contain 40 hex digits"
    );
    let address: [u8; 20] = hex::decode(body)?.try_into().expect("checked length");
    if body.bytes().any(|b| b.is_ascii_lowercase()) && body.bytes().any(|b| b.is_ascii_uppercase())
    {
        ensure!(
            checksum(&address) == text,
            "Invalid EIP-55 address checksum"
        );
    }
    ensure!(address != [0; 20], "Refusing the zero burn address");
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_encoding_matrix() {
        let text = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let expected = parse(text).unwrap();
        assert_eq!(parse(&text.to_ascii_lowercase()).unwrap(), expected);
        assert_eq!(
            parse(&format!("0x{}", text[2..].to_ascii_uppercase())).unwrap(),
            expected
        );
        for invalid in [
            "0X5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAez",
            "vitalik.eth",
            "ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn standard_bip44_account_and_eip55_vectors() {
        let mnemonic: bip39::Mnemonic =
            "test test test test test test test test test test test junk"
                .parse()
                .unwrap();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &mnemonic.to_seed("")).unwrap();
        assert_eq!(
            checksum(&from_key(&derive(&master, 0).unwrap())),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            checksum(&from_key(&derive(&master, 1).unwrap())),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        );
        for vector in [
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert_eq!(checksum(&parse(vector).unwrap()), vector);
        }
        assert!(parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee").is_err());
        assert!(parse("0x0000000000000000000000000000000000000000").is_err());
        assert!(parse("bc1qexample").is_err());
    }
}

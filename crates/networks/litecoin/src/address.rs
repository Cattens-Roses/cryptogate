use anyhow::{bail, Result};
use bech32::{segwit, Hrp};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    ScriptBuf,
};
use std::str::FromStr;

pub fn derive(master: &Xpriv, change: bool, index: u32) -> Result<(SecretKey, ScriptBuf, String)> {
    if index >= (1 << 31) {
        bail!("Address index exceeds BIP32 range");
    }
    let path = DerivationPath::from_str(&format!("m/84'/2'/0'/{}/{index}", u8::from(change)))?;
    let secp = Secp256k1::new();
    let child = master.derive_priv(&secp, &path)?;
    let public = PublicKey::from_secret_key(&secp, &child.private_key);
    let hash = hash160::Hash::hash(&public.serialize()).to_byte_array();
    let script = ScriptBuf::from_bytes([&[0, 20][..], &hash].concat());
    let address = segwit::encode_v0(Hrp::parse("ltc")?, &hash)?;
    Ok((child.private_key, script, address))
}

/// Decode Litecoin addresses explicitly; Bitcoin network address checks are unsuitable.
pub fn script_for_address(address: &str) -> Result<ScriptBuf> {
    if address.to_ascii_lowercase().starts_with("ltc1") {
        let (hrp, version, program) = segwit::decode(address)?;
        if hrp != Hrp::parse("ltc")? {
            bail!("Expected a Litecoin mainnet address");
        }
        let v = version.to_u8();
        if !matches!((v, program.len()), (0, 20 | 32) | (1, 32)) {
            bail!("Unsupported witness program; use P2WPKH, P2WSH, or Taproot");
        }
        let opcode = if v == 0 { 0 } else { 0x50 + v };
        return Ok(ScriptBuf::from_bytes(
            [vec![opcode, program.len() as u8], program].concat(),
        ));
    }
    let bytes = bs58::decode(address).with_check(None).into_vec()?;
    if bytes.len() != 21 {
        bail!("Invalid address length");
    }
    let h = &bytes[1..];
    Ok(match bytes[0] {
        48 => ScriptBuf::from_bytes([&[0x76, 0xa9, 20][..], h, &[0x88, 0xac]].concat()),
        50 | 5 => ScriptBuf::from_bytes([&[0xa9, 20][..], h, &[0x87]].concat()),
        _ => bail!("Expected a Litecoin mainnet address"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_type_matrix() {
        for (version, length, opcode) in [(0, 20, 0), (0, 32, 0), (1, 32, 0x51)] {
            let program = vec![42; length];
            let text = segwit::encode(
                Hrp::parse("ltc").unwrap(),
                bech32::Fe32::try_from(version).unwrap(),
                &program,
            )
            .unwrap();
            let expected = ScriptBuf::from_bytes([vec![opcode, length as u8], program].concat());
            assert_eq!(script_for_address(&text).unwrap(), expected);
            assert_eq!(
                script_for_address(&text.to_ascii_uppercase()).unwrap(),
                expected
            );
            assert!(script_for_address(&format!("LTC{}", &text[3..])).is_err());
        }
        let hash = vec![42; 20];
        for prefix in [48, 50, 5] {
            let text = bs58::encode([vec![prefix], hash.clone()].concat())
                .with_check()
                .into_string();
            let expected = if prefix == 48 {
                [&[0x76, 0xa9, 20][..], &hash, &[0x88, 0xac]].concat()
            } else {
                [&[0xa9, 20][..], &hash, &[0x87]].concat()
            };
            assert_eq!(script_for_address(&text).unwrap().as_bytes(), expected);
        }
        for prefix in [0, 111, 58] {
            let text = bs58::encode([vec![prefix], hash.clone()].concat())
                .with_check()
                .into_string();
            assert!(script_for_address(&text).is_err());
        }
        let testnet = segwit::encode_v0(Hrp::parse("tltc").unwrap(), &hash).unwrap();
        assert!(script_for_address(&testnet).is_err());
        assert!(script_for_address("ltc1mwebexample").is_err());
        assert!(script_for_address("litecoin:Lexample").is_err());
    }

    #[test]
    fn litecoin_derivation_and_address_boundaries() {
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &[0u8; 64]).unwrap();
        let (_, script, address) = derive(&master, false, 0).unwrap();
        assert!(address.starts_with("ltc1q"));
        assert_eq!(script_for_address(&address).unwrap(), script);
        assert_ne!(derive(&master, true, 0).unwrap().1, script);
        let bitcoin_addr = segwit::encode_v0(Hrp::parse("bc").unwrap(), &[0; 20]).unwrap();
        assert!(script_for_address(&bitcoin_addr).is_err());
        let mut corrupt = address.clone();
        corrupt.pop();
        corrupt.push('x');
        assert!(script_for_address(&corrupt).is_err());
        for prefix in [48, 50, 5] {
            let a = bs58::encode([vec![prefix], vec![42; 20]].concat())
                .with_check()
                .into_string();
            assert!(script_for_address(&a).is_ok());
        }
        let wrong = bs58::encode([vec![0], vec![42; 20]].concat())
            .with_check()
            .into_string();
        assert!(script_for_address(&wrong).is_err());
    }
}

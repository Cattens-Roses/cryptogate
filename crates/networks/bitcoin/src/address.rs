use anyhow::{bail, Result};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Address, AddressType, CompressedPublicKey, Network, ScriptBuf,
};
use std::str::FromStr;

pub fn derive(master: &Xpriv, change: bool, index: u32) -> Result<(SecretKey, ScriptBuf, String)> {
    if index >= (1 << 31) {
        bail!("Address index exceeds BIP32 range");
    }
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/{}/{index}", u8::from(change)))?;
    let secp = Secp256k1::new();
    let child = master.derive_priv(&secp, &path)?;
    let public = CompressedPublicKey(PublicKey::from_secret_key(&secp, &child.private_key));
    let address = Address::p2wpkh(&public, Network::Bitcoin);
    Ok((
        child.private_key,
        address.script_pubkey(),
        address.to_string(),
    ))
}

pub fn script_for_address(address: &str) -> Result<ScriptBuf> {
    let address = Address::from_str(address)?.require_network(Network::Bitcoin)?;
    if !matches!(
        address.address_type(),
        Some(
            AddressType::P2pkh
                | AddressType::P2sh
                | AddressType::P2wpkh
                | AddressType::P2wsh
                | AddressType::P2tr
        )
    ) {
        bail!("Unsupported Bitcoin address type");
    }
    Ok(address.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mainnet_address_checks_and_derivation_are_network_specific() {
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &[0; 64]).unwrap();
        let (_, script, address) = derive(&master, false, 0).unwrap();
        assert!(address.starts_with("bc1q"));
        assert_eq!(script_for_address(&address).unwrap(), script);
        assert_ne!(derive(&master, true, 0).unwrap().1, script);
        assert!(derive(&master, false, 1 << 31).is_err());
        assert!(script_for_address("ltc1qmvjy56ag6xrkeg546tjpfnr9sc3cyrcr6z7ag2").is_err());
        let testnet = Address::p2wpkh(
            &CompressedPublicKey(PublicKey::from_secret_key(
                &Secp256k1::new(),
                &derive(&master, false, 0).unwrap().0,
            )),
            Network::Testnet,
        );
        assert!(script_for_address(&testnet.to_string()).is_err());
        let mut corrupt = address;
        corrupt.pop();
        corrupt.push('x');
        assert!(script_for_address(&corrupt).is_err());
        assert!(script_for_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_ok());
        assert!(script_for_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").is_ok());
    }

    #[test]
    fn official_bip84_receive_and_change_vectors() {
        let mnemonic = bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &mnemonic.to_seed("")).unwrap();
        assert_eq!(
            derive(&master, false, 0).unwrap().2,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            derive(&master, false, 1).unwrap().2,
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            derive(&master, true, 0).unwrap().2,
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }
}

use anyhow::{ensure, Result};
use myotis_core::{
    keccak::keccak256,
    nodekey::NodeKey,
    rlp::{self, Item},
};

pub const TRANSFER_GAS: u64 = 21_000;
pub const GWEI: u128 = 1_000_000_000;

fn scalar(value: u128) -> Item {
    let bytes = value.to_be_bytes();
    Item::Bytes(
        bytes
            .iter()
            .skip_while(|byte| **byte == 0)
            .copied()
            .collect(),
    )
}

/// Mainnet EIP-1559, native ETH only, empty calldata and access list.
pub fn sign(
    key: &NodeKey,
    nonce: u64,
    recipient: [u8; 20],
    amount: u128,
    max_fee: u128,
    tip: u128,
) -> Result<Vec<u8>> {
    ensure!(
        amount > 0 && tip <= max_fee,
        "Invalid transfer amount or fee cap"
    );
    let mut fields = vec![
        scalar(1),
        scalar(nonce.into()),
        scalar(tip),
        scalar(max_fee),
        scalar(TRANSFER_GAS.into()),
        Item::Bytes(recipient.to_vec()),
        scalar(amount),
        Item::Bytes(vec![]),
        Item::List(vec![]),
    ];
    let mut unsigned = vec![2];
    unsigned.extend(rlp::encode(&Item::List(fields.clone())));
    let signature = key
        .sign_hash(&keccak256(&unsigned))
        .map_err(|error| anyhow::anyhow!(error.0))?;
    ensure!(signature[64] <= 1, "Unsupported Ethereum recovery id");
    fields.push(scalar(signature[64].into()));
    for half in signature[..64].chunks_exact(32) {
        fields.push(Item::Bytes(
            half.iter()
                .skip_while(|byte| **byte == 0)
                .copied()
                .collect(),
        ));
    }
    let mut raw = vec![2];
    raw.extend(rlp::encode(&Item::List(fields)));
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_transfer_recovers_sender_and_binds_mainnet_and_fee_cap() {
        let key = NodeKey::from_secret_bytes(&[1; 32]).unwrap();
        let raw = sign(
            &key,
            9,
            [2; 20],
            120_000_000 * 10u128.pow(18),
            30 * GWEI,
            GWEI,
        )
        .unwrap();
        let tx = myotis_net::el::tx::decode_sendable(&raw).unwrap();
        assert_eq!(tx.chain_id, Some(1));
        assert_eq!(tx.from, Some(crate::address::from_key(&key)));
        assert_eq!(tx.to, Some([2; 20]));
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.gas, TRANSFER_GAS);
        assert_eq!(tx.max_fee_per_gas, Some(30 * GWEI));
        assert_eq!(
            tx.value,
            (120_000_000 * 10u128.pow(18))
                .to_be_bytes()
                .iter()
                .skip_while(|b| **b == 0)
                .copied()
                .collect::<Vec<_>>()
        );
        assert!(myotis_net::el::tx::check_chain(&tx, 2).is_err());
        let mut corrupted = raw.clone();
        corrupted[10] ^= 1;
        assert_ne!(
            myotis_net::el::tx::decode_sendable(&corrupted)
                .ok()
                .and_then(|tx| tx.from),
            tx.from
        );
    }
}

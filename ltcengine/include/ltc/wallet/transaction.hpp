#pragma once
#include "ltc/wallet/script.hpp"
#include "ltc/util/bytes.hpp"
#include <string>
#include <vector>

namespace ltc {

struct OutPoint {
  Hash256 txid{};
  uint32_t vout = 0;
};

struct TxIn {
  OutPoint prev;
  Bytes script_sig;
  uint32_t sequence = 0xffffffffu;
  std::vector<Bytes> witness_stack;
};

struct TxOut {
  int64_t value = 0;
  Bytes script_pubkey;
};

struct Transaction {
  int32_t version = 2;
  std::vector<TxIn> vin;
  std::vector<TxOut> vout;
  uint32_t locktime = 0;

  Bytes serialize(bool witness = true) const;
  Hash256 txid() const;
  Hash256 wtxid() const;
  size_t weight() const;
  size_t vsize() const;
};

Transaction deserialize_tx(const Bytes& raw);
// Parse one tx and advance p; does not require p==end after.
Transaction deserialize_tx_at(const uint8_t*& p, const uint8_t* end);

struct Utxo {
  OutPoint outpoint;
  int64_t value = 0;
  Bytes script_pubkey;
  uint32_t height = 0;
  uint32_t key_index = 0;
  AddressType address_type = AddressType::P2WPKH;
  bool spent = false;
};

Hash256 sighash_legacy(const Transaction& tx, size_t input_index, const Bytes& script_code,
                       uint32_t hash_type = 1);
Hash256 sighash_bip143(const Transaction& tx, size_t input_index, const Bytes& script_code,
                       int64_t amount, uint32_t hash_type = 1);
Hash256 sighash_taproot_keypath(const Transaction& tx, size_t input_index,
                                const std::vector<int64_t>& amounts,
                                const std::vector<Bytes>& script_pubkeys, uint32_t hash_type = 0);

void sign_input_p2pkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey);
void sign_input_p2wpkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey,
                       int64_t amount);
void sign_input_p2sh_p2wpkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey,
                            int64_t amount);
void sign_input_p2tr(Transaction& tx, size_t index, const Bytes& priv32,
                     const std::vector<int64_t>& amounts, const std::vector<Bytes>& spks);

Transaction build_send(std::vector<Utxo>& utxos, const std::string& to_address, int64_t amount,
                       const std::string& change_address, int64_t fee_rate_sat_vb,
                       std::vector<size_t>& selected_indices);

}  // namespace ltc

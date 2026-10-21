#pragma once
#include "ltc/net/spv.hpp"
#include "ltc/wallet/hd.hpp"
#include "ltc/wallet/script.hpp"
#include "ltc/wallet/transaction.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ltc {

enum class WalletAddressType {
  Legacy,   // BIP44 P2PKH
  Nested,   // BIP49 P2SH-P2WPKH
  Native,   // BIP84 P2WPKH
  Taproot,  // BIP86 P2TR
};

struct WatchedAddress {
  std::string address;
  Bytes script_pubkey;
  Bytes redeem_script;  // BIP49
  Bytes pubkey;
  Bytes privkey;
  uint32_t index = 0;
  bool change = false;
  WalletAddressType type = WalletAddressType::Native;
};

class Wallet {
 public:
  static Wallet create_new(const std::string& data_dir, const std::string& password,
                           int strength_bits = 128, const std::string& bip39_passphrase = "");
  static Wallet import_mnemonic(const std::string& data_dir, const std::string& mnemonic,
                                const std::string& password,
                                const std::string& bip39_passphrase = "");
  static Wallet load(const std::string& data_dir, const std::string& password);

  void save(const std::string& password) const;

  const std::string& mnemonic() const { return mnemonic_; }
  const std::string& data_dir() const { return data_dir_; }

  // Gap-limit address generation (default 20).
  void set_gap_limit(uint32_t gap) { gap_limit_ = gap; }
  uint32_t gap_limit() const { return gap_limit_; }

  std::string get_new_address(WalletAddressType type = WalletAddressType::Native);
  std::vector<WatchedAddress> all_addresses() const;
  std::vector<Bytes> watched_scripts() const;

  const std::vector<Utxo>& utxos() const { return utxos_; }
  int64_t balance() const;

  // Build bloom from watched scripts/pubkeys and sync via SpvNode.
  void sync(net::SpvNode& spv, net::SpvNode::ProgressFn on_progress = {});

  // Apply a network/matched transaction to the UTXO set (used by background sync).
  void ingest_tx(const Transaction& tx, uint32_t height);

  // Scripts + UTXO outpoints for BIP37 bloom construction.
  void fill_bloom(net::BloomFilter& bloom) const;

  // Last height fully scanned with the bloom filter (for catch-up rescan).
  uint32_t filter_height() const { return filter_height_; }
  void set_filter_height(uint32_t h);

  // Create, sign, broadcast a payment. Returns txid hex (display order).
  std::string send(net::SpvNode& spv, const std::string& to_address, int64_t amount,
                   int64_t fee_rate_sat_vb = -1);

 private:
  Wallet() = default;

  void init_from_seed(const Bytes& seed);
  void derive_gap(WalletAddressType type, bool change);
  WatchedAddress derive_one(WalletAddressType type, bool change, uint32_t index);
  ExtKey account_root(WalletAddressType type) const;
  void ensure_look_ahead();
  void on_tx(const Transaction& tx, uint32_t height);
  Bytes encrypt_seed(const std::string& password, Bytes& salt_out, Bytes& iv_out) const;
  static Bytes decrypt_seed(const std::string& password, const Bytes& salt, const Bytes& iv,
                            const Bytes& ciphertext);
  std::string wallet_path() const;
  std::string utxo_path() const;
  std::string meta_path() const;
  void save_utxos() const;
  void load_utxos();
  void save_meta() const;
  void load_meta();

  std::string data_dir_;
  std::string mnemonic_;
  Bytes seed_;
  ExtKey master_;

  uint32_t gap_limit_ = 20;
  // next external index per type
  uint32_t next_recv_[4] = {0, 0, 0, 0};
  uint32_t next_change_[4] = {0, 0, 0, 0};
  // highest used (+1) for gap tracking
  uint32_t used_recv_[4] = {0, 0, 0, 0};
  uint32_t used_change_[4] = {0, 0, 0, 0};

  std::vector<WatchedAddress> addresses_;
  std::unordered_map<std::string, size_t> script_index_;  // hex(script) -> addresses_ idx
  std::vector<Utxo> utxos_;
  uint32_t filter_height_ = 0;  // last bloom-scanned block height
};

const char* wallet_address_type_name(WalletAddressType t);
WalletAddressType wallet_address_type_from_name(const std::string& name);

}  // namespace ltc

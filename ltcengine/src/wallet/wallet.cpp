#include "ltc/wallet/wallet.hpp"

#include "ltc/crypto/hash.hpp"
#include "ltc/crypto/random.hpp"
#include "ltc/params.hpp"
#include "ltc/util/fs.hpp"
#include "ltc/wallet/bip39.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace ltc {
namespace {

int type_index(WalletAddressType t) {
  switch (t) {
    case WalletAddressType::Legacy:
      return 0;
    case WalletAddressType::Nested:
      return 1;
    case WalletAddressType::Native:
      return 2;
    case WalletAddressType::Taproot:
      return 3;
  }
  return 2;
}

std::string script_key(const Bytes& spk) { return to_hex(spk); }

Bytes p2sh_p2wpkh_redeem(const Hash160& h160) {
  Bytes r;
  r.push_back(0x00);
  r.push_back(0x14);
  r.insert(r.end(), h160.begin(), h160.end());
  return r;
}

}  // namespace

const char* wallet_address_type_name(WalletAddressType t) {
  switch (t) {
    case WalletAddressType::Legacy:
      return "legacy";
    case WalletAddressType::Nested:
      return "nested";
    case WalletAddressType::Native:
      return "native";
    case WalletAddressType::Taproot:
      return "taproot";
  }
  return "native";
}

WalletAddressType wallet_address_type_from_name(const std::string& name) {
  if (name == "legacy") return WalletAddressType::Legacy;
  if (name == "nested") return WalletAddressType::Nested;
  if (name == "taproot") return WalletAddressType::Taproot;
  return WalletAddressType::Native;
}

std::string Wallet::wallet_path() const { return fs::join(data_dir_, "wallet.dat"); }
std::string Wallet::utxo_path() const { return fs::join(data_dir_, "utxos.dat"); }
std::string Wallet::meta_path() const { return fs::join(data_dir_, "wallet.meta"); }

void Wallet::save_meta() const {
  std::ostringstream oss;
  oss << "META1\n";
  oss << "gap=" << gap_limit_ << "\n";
  oss << "filter_height=" << filter_height_ << "\n";
  for (int i = 0; i < 4; ++i) {
    oss << "used_recv_" << i << "=" << used_recv_[i] << "\n";
    oss << "used_change_" << i << "=" << used_change_[i] << "\n";
    oss << "next_recv_" << i << "=" << next_recv_[i] << "\n";
    oss << "next_change_" << i << "=" << next_change_[i] << "\n";
  }
  fs::write_file(meta_path(), oss.str());
}

void Wallet::load_meta() {
  if (!fs::file_exists(meta_path())) return;
  std::string text = fs::read_text(meta_path());
  std::istringstream iss(text);
  std::string line;
  if (!std::getline(iss, line) || line != "META1") return;
  while (std::getline(iss, line)) {
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);
    if (key == "gap")
      gap_limit_ = static_cast<uint32_t>(std::stoul(val));
    else if (key == "filter_height")
      filter_height_ = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("used_recv_", 0) == 0)
      used_recv_[std::stoi(key.substr(10))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("used_change_", 0) == 0)
      used_change_[std::stoi(key.substr(12))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("next_recv_", 0) == 0)
      next_recv_[std::stoi(key.substr(10))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("next_change_", 0) == 0)
      next_change_[std::stoi(key.substr(12))] = static_cast<uint32_t>(std::stoul(val));
  }
}

void Wallet::set_filter_height(uint32_t h) {
  if (h <= filter_height_) return;
  filter_height_ = h;
  save_meta();
}

ExtKey Wallet::account_root(WalletAddressType type) const {
  std::string path;
  switch (type) {
    case WalletAddressType::Legacy:
      path = "m/44'/2'/0'";
      break;
    case WalletAddressType::Nested:
      path = "m/49'/2'/0'";
      break;
    case WalletAddressType::Native:
      path = "m/84'/2'/0'";
      break;
    case WalletAddressType::Taproot:
      path = "m/86'/2'/0'";
      break;
  }
  return derive_path(master_, path);
}

WatchedAddress Wallet::derive_one(WalletAddressType type, bool change, uint32_t index) {
  ExtKey acct = account_root(type);
  ExtKey chain = derive_child(acct, change ? 1u : 0u);
  ExtKey child = derive_child(chain, index);
  if (!child.is_private || child.key.size() != 32)
    throw std::runtime_error("expected private key at derivation path");

  WatchedAddress wa;
  wa.type = type;
  wa.change = change;
  wa.index = index;
  wa.privkey = child.key;
  wa.pubkey = priv_to_pub(child.key, true);

  Hash160 h160 = hash160(wa.pubkey);
  switch (type) {
    case WalletAddressType::Legacy:
      wa.script_pubkey = script_p2pkh(h160);
      wa.address = address_p2pkh(h160);
      break;
    case WalletAddressType::Nested: {
      wa.redeem_script = p2sh_p2wpkh_redeem(h160);
      Hash160 sh = hash160(wa.redeem_script);
      wa.script_pubkey = script_p2sh(sh);
      wa.address = address_p2sh(sh);
      break;
    }
    case WalletAddressType::Native:
      wa.script_pubkey = script_p2wpkh(h160);
      wa.address = address_p2wpkh(h160);
      break;
    case WalletAddressType::Taproot: {
      // BIP86: address commits to tweaked output key, not the internal key.
      Bytes output = taproot_output_xonly(child.key);
      wa.pubkey = output;
      wa.script_pubkey = script_p2tr(output);
      wa.address = address_p2tr(output);
      break;
    }
  }
  return wa;
}

void Wallet::derive_gap(WalletAddressType type, bool change) {
  int ti = type_index(type);
  uint32_t& next = change ? next_change_[ti] : next_recv_[ti];
  uint32_t used = change ? used_change_[ti] : used_recv_[ti];
  uint32_t target = used + gap_limit_;
  while (next < target) {
    WatchedAddress wa = derive_one(type, change, next);
    script_index_[script_key(wa.script_pubkey)] = addresses_.size();
    addresses_.push_back(std::move(wa));
    ++next;
  }
}

void Wallet::ensure_look_ahead() {
  for (int t = 0; t < 4; ++t) {
    auto type = static_cast<WalletAddressType>(t);
    derive_gap(type, false);
    derive_gap(type, true);
  }
}

void Wallet::init_from_seed(const Bytes& seed) {
  seed_ = seed;
  master_ = master_from_seed(seed_);
  addresses_.clear();
  script_index_.clear();
  for (int i = 0; i < 4; ++i) {
    next_recv_[i] = next_change_[i] = 0;
    used_recv_[i] = used_change_[i] = 0;
  }
  ensure_look_ahead();
}

Wallet Wallet::create_new(const std::string& data_dir, const std::string& password, int strength_bits,
                          const std::string& bip39_passphrase) {
  Wallet w;
  w.data_dir_ = data_dir;
  fs::ensure_dir(data_dir);
  w.mnemonic_ = generate_mnemonic(strength_bits);
  Bytes seed = mnemonic_to_seed(w.mnemonic_, bip39_passphrase);
  w.init_from_seed(seed);
  w.save(password);
  return w;
}

Wallet Wallet::import_mnemonic(const std::string& data_dir, const std::string& mnemonic,
                               const std::string& password, const std::string& bip39_passphrase) {
  if (!mnemonic_is_valid(mnemonic)) throw std::runtime_error("invalid mnemonic");
  Wallet w;
  w.data_dir_ = data_dir;
  fs::ensure_dir(data_dir);
  w.mnemonic_ = mnemonic;
  Bytes seed = mnemonic_to_seed(mnemonic, bip39_passphrase);
  w.init_from_seed(seed);
  w.save(password);
  return w;
}

Bytes Wallet::encrypt_seed(const std::string& password, Bytes& salt_out, Bytes& iv_out) const {
  salt_out = random_bytes(16);
  iv_out = random_bytes(16);
  Bytes dk = pbkdf2_hmac_sha512(password, std::string(salt_out.begin(), salt_out.end()), 100000, 64);
  Bytes key(dk.begin(), dk.begin() + 32);
  return aes256_cbc_encrypt(key, iv_out, seed_);
}

Bytes Wallet::decrypt_seed(const std::string& password, const Bytes& salt, const Bytes& iv,
                           const Bytes& ciphertext) {
  Bytes dk = pbkdf2_hmac_sha512(password, std::string(salt.begin(), salt.end()), 100000, 64);
  Bytes key(dk.begin(), dk.begin() + 32);
  return aes256_cbc_decrypt(key, iv, ciphertext);
}

void Wallet::save(const std::string& password) const {
  Bytes salt, iv;
  Bytes ct = encrypt_seed(password, salt, iv);
  std::ostringstream oss;
  oss << "LTCWALLET1\n";
  oss << "mnemonic=" << mnemonic_ << "\n";
  oss << "salt=" << to_hex(salt) << "\n";
  oss << "iv=" << to_hex(iv) << "\n";
  oss << "seed_enc=" << to_hex(ct) << "\n";
  oss << "gap=" << gap_limit_ << "\n";
  for (int i = 0; i < 4; ++i) {
    oss << "used_recv_" << i << "=" << used_recv_[i] << "\n";
    oss << "used_change_" << i << "=" << used_change_[i] << "\n";
    oss << "next_recv_" << i << "=" << next_recv_[i] << "\n";
    oss << "next_change_" << i << "=" << next_change_[i] << "\n";
  }
  fs::write_file(wallet_path(), oss.str());
  save_meta();
  save_utxos();
}

void Wallet::save_utxos() const {
  std::ostringstream oss;
  oss << "UTXO1\n";
  for (const auto& u : utxos_) {
    oss << to_hex(u.outpoint.txid.data(), 32) << " " << u.outpoint.vout << " " << u.value << " "
        << u.height << " " << u.key_index << " " << static_cast<int>(u.address_type) << " "
        << (u.spent ? 1 : 0) << " " << to_hex(u.script_pubkey) << "\n";
  }
  fs::write_file(utxo_path(), oss.str());
}

void Wallet::load_utxos() {
  utxos_.clear();
  if (!fs::file_exists(utxo_path())) return;
  std::string text = fs::read_text(utxo_path());
  std::istringstream iss(text);
  std::string line;
  if (!std::getline(iss, line) || line != "UTXO1") return;
  while (std::getline(iss, line)) {
    if (line.empty()) continue;
    std::istringstream ls(line);
    std::string txid_hex, spk_hex;
    uint32_t vout = 0, height = 0, key_index = 0;
    int64_t value = 0;
    int atype = 0, spent = 0;
    ls >> txid_hex >> vout >> value >> height >> key_index >> atype >> spent >> spk_hex;
    Utxo u;
    Bytes txid = from_hex(txid_hex);
    if (txid.size() != 32) continue;
    std::memcpy(u.outpoint.txid.data(), txid.data(), 32);
    u.outpoint.vout = vout;
    u.value = value;
    u.height = height;
    u.key_index = key_index;
    u.address_type = static_cast<AddressType>(atype);
    u.spent = spent != 0;
    u.script_pubkey = from_hex(spk_hex);
    utxos_.push_back(std::move(u));
  }
}

Wallet Wallet::load(const std::string& data_dir, const std::string& password) {
  Wallet w;
  w.data_dir_ = data_dir;
  std::string text = fs::read_text(fs::join(data_dir, "wallet.dat"));
  std::istringstream iss(text);
  std::string line;
  if (!std::getline(iss, line) || line != "LTCWALLET1")
    throw std::runtime_error("bad wallet file magic");

  std::string salt_hex, iv_hex, seed_enc_hex;
  while (std::getline(iss, line)) {
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);
    if (key == "mnemonic")
      w.mnemonic_ = val;
    else if (key == "salt")
      salt_hex = val;
    else if (key == "iv")
      iv_hex = val;
    else if (key == "seed_enc")
      seed_enc_hex = val;
    else if (key == "gap")
      w.gap_limit_ = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("used_recv_", 0) == 0)
      w.used_recv_[std::stoi(key.substr(10))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("used_change_", 0) == 0)
      w.used_change_[std::stoi(key.substr(12))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("next_recv_", 0) == 0)
      w.next_recv_[std::stoi(key.substr(10))] = static_cast<uint32_t>(std::stoul(val));
    else if (key.rfind("next_change_", 0) == 0)
      w.next_change_[std::stoi(key.substr(12))] = static_cast<uint32_t>(std::stoul(val));
  }

  Bytes salt = from_hex(salt_hex);
  Bytes iv = from_hex(iv_hex);
  Bytes ct = from_hex(seed_enc_hex);
  w.seed_ = decrypt_seed(password, salt, iv, ct);
  w.master_ = master_from_seed(w.seed_);
  w.load_meta();

  // Rebuild address pool from counters (reset next and re-derive).
  uint32_t saved_next_recv[4], saved_next_change[4];
  for (int i = 0; i < 4; ++i) {
    saved_next_recv[i] = std::max(w.next_recv_[i], w.used_recv_[i] + w.gap_limit_);
    saved_next_change[i] = std::max(w.next_change_[i], w.used_change_[i] + w.gap_limit_);
    w.next_recv_[i] = 0;
    w.next_change_[i] = 0;
  }
  w.addresses_.clear();
  w.script_index_.clear();
  for (int t = 0; t < 4; ++t) {
    auto type = static_cast<WalletAddressType>(t);
    while (w.next_recv_[t] < saved_next_recv[t]) {
      WatchedAddress wa = w.derive_one(type, false, w.next_recv_[t]);
      w.script_index_[script_key(wa.script_pubkey)] = w.addresses_.size();
      w.addresses_.push_back(std::move(wa));
      ++w.next_recv_[t];
    }
    while (w.next_change_[t] < saved_next_change[t]) {
      WatchedAddress wa = w.derive_one(type, true, w.next_change_[t]);
      w.script_index_[script_key(wa.script_pubkey)] = w.addresses_.size();
      w.addresses_.push_back(std::move(wa));
      ++w.next_change_[t];
    }
  }
  w.load_utxos();
  return w;
}

std::string Wallet::get_new_address(WalletAddressType type) {
  int ti = type_index(type);
  // Hand out the next unused receive address within the gap window.
  uint32_t idx = used_recv_[ti];
  derive_gap(type, false);
  // Find address with this index.
  for (auto& a : addresses_) {
    if (a.type == type && !a.change && a.index == idx) {
      used_recv_[ti] = idx + 1;
      ensure_look_ahead();
      save_meta();
      return a.address;
    }
  }
  WatchedAddress wa = derive_one(type, false, idx);
  script_index_[script_key(wa.script_pubkey)] = addresses_.size();
  std::string addr = wa.address;
  addresses_.push_back(std::move(wa));
  if (next_recv_[ti] <= idx) next_recv_[ti] = idx + 1;
  used_recv_[ti] = idx + 1;
  ensure_look_ahead();
  save_meta();
  return addr;
}

std::vector<WatchedAddress> Wallet::all_addresses() const { return addresses_; }

std::vector<Bytes> Wallet::watched_scripts() const {
  std::vector<Bytes> out;
  out.reserve(addresses_.size() * 2);
  for (const auto& a : addresses_) {
    out.push_back(a.script_pubkey);
    if (!a.pubkey.empty()) out.push_back(a.pubkey);
    if (!a.redeem_script.empty()) out.push_back(a.redeem_script);
    // Also watch hash160 of pubkey for BIP37 matching flexibility.
    if (a.pubkey.size() == 33) {
      Hash160 h = hash160(a.pubkey);
      out.emplace_back(h.begin(), h.end());
    }
  }
  return out;
}

int64_t Wallet::balance() const {
  int64_t sum = 0;
  for (const auto& u : utxos_)
    if (!u.spent) sum += u.value;
  return sum;
}

void Wallet::on_tx(const Transaction& tx, uint32_t height) {
  Hash256 tid = tx.txid();
  // Mark spent inputs.
  for (const auto& in : tx.vin) {
    for (auto& u : utxos_) {
      if (!u.spent && u.outpoint.txid == in.prev.txid && u.outpoint.vout == in.prev.vout) {
        u.spent = true;
      }
    }
  }
  // Collect matching outputs.
  for (uint32_t i = 0; i < tx.vout.size(); ++i) {
    const auto& o = tx.vout[i];
    auto it = script_index_.find(script_key(o.script_pubkey));
    if (it == script_index_.end()) continue;
    const WatchedAddress& wa = addresses_[it->second];
    int ti = type_index(wa.type);
    if (wa.change) {
      if (wa.index + 1 > used_change_[ti]) used_change_[ti] = wa.index + 1;
    } else {
      if (wa.index + 1 > used_recv_[ti]) used_recv_[ti] = wa.index + 1;
    }

    bool exists = false;
    for (const auto& u : utxos_) {
      if (u.outpoint.txid == tid && u.outpoint.vout == i) {
        exists = true;
        break;
      }
    }
    if (exists) continue;

    Utxo u;
    u.outpoint.txid = tid;
    u.outpoint.vout = i;
    u.value = o.value;
    u.script_pubkey = o.script_pubkey;
    u.height = height;
    u.key_index = wa.index;
    switch (wa.type) {
      case WalletAddressType::Legacy:
        u.address_type = AddressType::P2PKH;
        break;
      case WalletAddressType::Nested:
        u.address_type = AddressType::P2SH;
        break;
      case WalletAddressType::Native:
        u.address_type = AddressType::P2WPKH;
        break;
      case WalletAddressType::Taproot:
        u.address_type = AddressType::P2TR;
        break;
    }
    u.spent = false;
    utxos_.push_back(std::move(u));
  }
  ensure_look_ahead();
  save_meta();
  save_utxos();
}

void Wallet::sync(net::SpvNode& spv, net::SpvNode::ProgressFn on_progress) {
  ensure_look_ahead();
  net::BloomFilter bloom(256, 0.0001, random_u32(), net::BLOOM_UPDATE_ALL);
  fill_bloom(bloom);
  spv.set_bloom(bloom);
  if (!spv.has_peer()) {
    if (!spv.connect_peers()) throw std::runtime_error("no Litecoin P2P peers available");
  }
  spv.sync_headers(on_progress);
  spv.send_filterload();
  uint32_t from = filter_height_;
  uint32_t tip = spv.tip_height();
  constexpr uint32_t kFirstWindow = 10000;
  if (from == 0 && tip > kFirstWindow) from = tip - kFirstWindow;
  if (from < tip) {
    uint32_t scanned = spv.rescan_filtered(
        from, [this](const Transaction& tx, uint32_t height, const Hash256&) { ingest_tx(tx, height); },
        on_progress);
    set_filter_height(scanned);
  }
  spv.sync_filtered(
      [this](const Transaction& tx, uint32_t height, const Hash256&) { ingest_tx(tx, height); },
      on_progress, 60000);
  if (spv.tip_height() > filter_height_) set_filter_height(spv.tip_height());
}

void Wallet::ingest_tx(const Transaction& tx, uint32_t height) { on_tx(tx, height); }

void Wallet::fill_bloom(net::BloomFilter& bloom) const {
  // const_cast look-ahead not available; scripts already gap-derived on load/create.
  for (const auto& s : watched_scripts()) bloom.insert(s);
  for (const auto& u : utxos_) {
    if (u.spent) continue;
    Bytes op;
    append_bytes(op, u.outpoint.txid.data(), 32);
    append_u32le(op, u.outpoint.vout);
    bloom.insert(op);
  }
}

std::string Wallet::send(net::SpvNode& spv, const std::string& to_address, int64_t amount,
                         int64_t fee_rate_sat_vb) {
  if (fee_rate_sat_vb < 0) fee_rate_sat_vb = params::kDefaultFeeRateSatPerVb;
  ensure_look_ahead();

  // Prefer native segwit change.
  int ti = type_index(WalletAddressType::Native);
  uint32_t cidx = used_change_[ti];
  derive_gap(WalletAddressType::Native, true);
  std::string change_addr;
  for (const auto& a : addresses_) {
    if (a.type == WalletAddressType::Native && a.change && a.index == cidx) {
      change_addr = a.address;
      break;
    }
  }
  if (change_addr.empty()) {
    WatchedAddress wa = derive_one(WalletAddressType::Native, true, cidx);
    change_addr = wa.address;
    script_index_[script_key(wa.script_pubkey)] = addresses_.size();
    addresses_.push_back(std::move(wa));
  }

  std::vector<Utxo> available;
  for (const auto& u : utxos_)
    if (!u.spent) available.push_back(u);

  std::vector<size_t> selected;
  Transaction tx = build_send(available, to_address, amount, change_addr, fee_rate_sat_vb, selected);

  // Map selected UTXOs back and sign.
  std::vector<int64_t> amounts;
  std::vector<Bytes> spks;
  amounts.reserve(tx.vin.size());
  spks.reserve(tx.vin.size());

  for (size_t i = 0; i < tx.vin.size(); ++i) {
    const OutPoint& prev = tx.vin[i].prev;
    const Utxo* u = nullptr;
    for (const auto& cand : utxos_) {
      if (cand.outpoint.txid == prev.txid && cand.outpoint.vout == prev.vout) {
        u = &cand;
        break;
      }
    }
    if (!u) throw std::runtime_error("selected utxo missing");
    amounts.push_back(u->value);
    spks.push_back(u->script_pubkey);

    auto sit = script_index_.find(script_key(u->script_pubkey));
    if (sit == script_index_.end()) throw std::runtime_error("no key for utxo");
    const WatchedAddress& wa = addresses_[sit->second];

    switch (wa.type) {
      case WalletAddressType::Legacy:
        sign_input_p2pkh(tx, i, wa.privkey, wa.pubkey);
        break;
      case WalletAddressType::Nested:
        sign_input_p2sh_p2wpkh(tx, i, wa.privkey, priv_to_pub(wa.privkey, true), u->value);
        break;
      case WalletAddressType::Native:
        sign_input_p2wpkh(tx, i, wa.privkey, wa.pubkey, u->value);
        break;
      case WalletAddressType::Taproot:
        sign_input_p2tr(tx, i, wa.privkey, amounts, spks);
        break;
    }
  }

  // Advance change index if change output present.
  if (tx.vout.size() >= 2) {
    used_change_[ti] = cidx + 1;
    ensure_look_ahead();
    save_meta();
  }

  spv.broadcast_tx(tx);
  on_tx(tx, 0);
  Hash256 id = tx.txid();
  return to_hex(id.data(), id.size(), true);
}

}  // namespace ltc

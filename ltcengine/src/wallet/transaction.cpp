#include "ltc/wallet/transaction.hpp"
#include "ltc/wallet/hd.hpp"
#include "ltc/crypto/hash.hpp"
#include "ltc/params.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace ltc {
namespace {

constexpr uint8_t OP_0 = 0x00;
constexpr uint32_t SIGHASH_ALL = 1;
constexpr uint32_t SIGHASH_NONE = 2;
constexpr uint32_t SIGHASH_SINGLE = 3;
constexpr uint32_t SIGHASH_ANYONECANPAY = 0x80;

void serialize_outpoint(Bytes& out, const OutPoint& op) {
  append_bytes(out, op.txid.data(), op.txid.size());
  append_u32le(out, op.vout);
}

void serialize_txout(Bytes& out, const TxOut& o) {
  append_u64le(out, uint64_t(o.value));
  append_varbytes(out, o.script_pubkey);
}

bool has_witness(const Transaction& tx) {
  for (const auto& in : tx.vin) {
    if (!in.witness_stack.empty()) return true;
  }
  return false;
}

Bytes script_code_p2pkh(const Bytes& pubkey) {
  Hash160 h = hash160(pubkey);
  return script_p2pkh(h);
}

Bytes script_code_p2wpkh(const Bytes& pubkey) {
  // BIP143: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  Hash160 h = hash160(pubkey);
  return script_p2pkh(h);
}

Bytes redeem_p2sh_p2wpkh(const Bytes& pubkey) {
  Hash160 h = hash160(pubkey);
  Bytes redeem;
  redeem.push_back(OP_0);
  redeem.push_back(0x14);
  append_bytes(redeem, h.data(), h.size());
  return redeem;
}

Bytes push_script(const Bytes& data) {
  Bytes out;
  if (data.size() < 0x4c) {
    out.push_back(uint8_t(data.size()));
  } else if (data.size() <= 0xff) {
    out.push_back(0x4c);
    out.push_back(uint8_t(data.size()));
  } else {
    throw std::runtime_error("script push too large");
  }
  append_bytes(out, data);
  return out;
}

size_t estimate_input_vsize(AddressType t) {
  switch (t) {
    case AddressType::P2PKH:
      return 148;
    case AddressType::P2SH:  // assume P2SH-P2WPKH
      return 91;
    case AddressType::P2WPKH:
      return 68;
    case AddressType::P2TR:
      return 58;
    case AddressType::P2WSH:
      return 105;
    default:
      return 68;
  }
}

size_t estimate_output_vsize(const Bytes& spk) {
  // 8 value + varint script len + script
  size_t script_len = spk.size();
  size_t varint = script_len < 0xfd ? 1 : 3;
  return 8 + varint + script_len;
}

Hash256 hash_outputs(const Transaction& tx) {
  Bytes buf;
  for (const auto& o : tx.vout) serialize_txout(buf, o);
  return double_sha256(buf);
}

Hash256 hash_prevouts(const Transaction& tx) {
  Bytes buf;
  for (const auto& in : tx.vin) serialize_outpoint(buf, in.prev);
  return double_sha256(buf);
}

Hash256 hash_sequences(const Transaction& tx) {
  Bytes buf;
  for (const auto& in : tx.vin) append_u32le(buf, in.sequence);
  return double_sha256(buf);
}

}  // namespace

Bytes Transaction::serialize(bool witness) const {
  Bytes out;
  append_u32le(out, uint32_t(version));
  bool ser_wit = witness && has_witness(*this);
  if (ser_wit) {
    append_u8(out, 0x00);  // marker
    append_u8(out, 0x01);  // flag
  }
  append_varint(out, vin.size());
  for (const auto& in : vin) {
    serialize_outpoint(out, in.prev);
    append_varbytes(out, in.script_sig);
    append_u32le(out, in.sequence);
  }
  append_varint(out, vout.size());
  for (const auto& o : vout) serialize_txout(out, o);
  if (ser_wit) {
    for (const auto& in : vin) {
      append_varint(out, in.witness_stack.size());
      for (const auto& item : in.witness_stack) append_varbytes(out, item);
    }
  }
  append_u32le(out, locktime);
  return out;
}

Hash256 Transaction::txid() const {
  return double_sha256(serialize(false));
}

Hash256 Transaction::wtxid() const {
  return double_sha256(serialize(true));
}

size_t Transaction::weight() const {
  Bytes with = serialize(true);
  Bytes without = serialize(false);
  // weight = base*3 + total; for non-segwit, with==without so weight=4*size
  if (!has_witness(*this)) return with.size() * 4;
  size_t total = with.size();
  size_t base = without.size();
  return base * 3 + total;
}

size_t Transaction::vsize() const {
  return (weight() + 3) / 4;
}

Transaction deserialize_tx_at(const uint8_t*& p, const uint8_t* end) {
  if (p + 4 > end) throw std::runtime_error("tx too short");
  Transaction tx;
  tx.version = int32_t(read_u32le(p));
  p += 4;
  bool witness = false;
  if (p < end && *p == 0x00) {
    ++p;
    if (p >= end || *p != 0x01) throw std::runtime_error("invalid witness flag");
    ++p;
    witness = true;
  }
  uint64_t nin = read_varint(p, end);
  tx.vin.resize(size_t(nin));
  for (auto& in : tx.vin) {
    if (p + 36 > end) throw std::runtime_error("truncated input");
    std::memcpy(in.prev.txid.data(), p, 32);
    p += 32;
    in.prev.vout = read_u32le(p);
    p += 4;
    in.script_sig = read_varbytes(p, end);
    if (p + 4 > end) throw std::runtime_error("truncated sequence");
    in.sequence = read_u32le(p);
    p += 4;
  }
  uint64_t nout = read_varint(p, end);
  tx.vout.resize(size_t(nout));
  for (auto& o : tx.vout) {
    if (p + 8 > end) throw std::runtime_error("truncated output");
    o.value = int64_t(read_u64le(p));
    p += 8;
    o.script_pubkey = read_varbytes(p, end);
  }
  if (witness) {
    for (auto& in : tx.vin) {
      uint64_t nstack = read_varint(p, end);
      in.witness_stack.resize(size_t(nstack));
      for (auto& item : in.witness_stack) item = read_varbytes(p, end);
    }
  }
  if (p + 4 > end) throw std::runtime_error("truncated locktime");
  tx.locktime = read_u32le(p);
  p += 4;
  return tx;
}

Transaction deserialize_tx(const Bytes& raw) {
  const uint8_t* p = raw.data();
  const uint8_t* end = raw.data() + raw.size();
  Transaction tx = deserialize_tx_at(p, end);
  if (p != end) throw std::runtime_error("trailing tx bytes");
  return tx;
}

Hash256 sighash_legacy(const Transaction& tx, size_t input_index, const Bytes& script_code,
                       uint32_t hash_type) {
  if (input_index >= tx.vin.size()) throw std::runtime_error("input index OOB");
  Transaction tmp = tx;
  for (size_t i = 0; i < tmp.vin.size(); ++i) {
    tmp.vin[i].script_sig.clear();
    tmp.vin[i].witness_stack.clear();
  }
  tmp.vin[input_index].script_sig = script_code;

  uint32_t base = hash_type & 0x1f;
  if (base == SIGHASH_NONE) {
    tmp.vout.clear();
    for (size_t i = 0; i < tmp.vin.size(); ++i)
      if (i != input_index) tmp.vin[i].sequence = 0;
  } else if (base == SIGHASH_SINGLE) {
    if (input_index >= tmp.vout.size()) {
      // Bitcoin quirk: returns 1
      Hash256 one{};
      one[31] = 1;
      return one;
    }
    tmp.vout.resize(input_index + 1);
    for (size_t i = 0; i < input_index; ++i) {
      tmp.vout[i].value = -1;
      tmp.vout[i].script_pubkey.clear();
    }
    for (size_t i = 0; i < tmp.vin.size(); ++i)
      if (i != input_index) tmp.vin[i].sequence = 0;
  }
  if (hash_type & SIGHASH_ANYONECANPAY) {
    TxIn keep = tmp.vin[input_index];
    tmp.vin.clear();
    tmp.vin.push_back(keep);
  }

  Bytes ser = tmp.serialize(false);
  append_u32le(ser, hash_type);
  return double_sha256(ser);
}

Hash256 sighash_bip143(const Transaction& tx, size_t input_index, const Bytes& script_code,
                       int64_t amount, uint32_t hash_type) {
  if (input_index >= tx.vin.size()) throw std::runtime_error("input index OOB");
  Hash256 zero{};
  zero.fill(0);

  Hash256 hp =
      (hash_type & SIGHASH_ANYONECANPAY) ? zero : hash_prevouts(tx);

  uint32_t base = hash_type & 0x1f;
  Hash256 hs = zero;
  if (!(hash_type & SIGHASH_ANYONECANPAY) && base != SIGHASH_SINGLE && base != SIGHASH_NONE)
    hs = hash_sequences(tx);

  Hash256 ho = zero;
  if (base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
    ho = hash_outputs(tx);
  } else if (base == SIGHASH_SINGLE && input_index < tx.vout.size()) {
    Bytes one;
    serialize_txout(one, tx.vout[input_index]);
    ho = double_sha256(one);
  }

  Bytes buf;
  append_u32le(buf, uint32_t(tx.version));
  append_bytes(buf, hp.data(), 32);
  append_bytes(buf, hs.data(), 32);
  serialize_outpoint(buf, tx.vin[input_index].prev);
  append_varbytes(buf, script_code);
  append_u64le(buf, uint64_t(amount));
  append_u32le(buf, tx.vin[input_index].sequence);
  append_bytes(buf, ho.data(), 32);
  append_u32le(buf, tx.locktime);
  append_u32le(buf, hash_type);
  return double_sha256(buf);
}

Hash256 sighash_taproot_keypath(const Transaction& tx, size_t input_index,
                                const std::vector<int64_t>& amounts,
                                const std::vector<Bytes>& script_pubkeys, uint32_t hash_type) {
  if (input_index >= tx.vin.size()) throw std::runtime_error("input index OOB");
  if (amounts.size() != tx.vin.size() || script_pubkeys.size() != tx.vin.size())
    throw std::runtime_error("taproot sighash missing amounts/spks");

  // BIP341: treat SIGHASH_DEFAULT (0) like ALL for hashing, but epoch/message differs.
  uint8_t ext_flag = 0;  // keypath
  uint8_t annex = 0;
  uint8_t spend_type = uint8_t((ext_flag << 1) + annex);

  Bytes ss;
  ss.push_back(0x00);  // epoch
  ss.push_back(uint8_t(hash_type));

  append_u32le(ss, uint32_t(tx.version));
  append_u32le(ss, tx.locktime);

  if (!(hash_type & SIGHASH_ANYONECANPAY)) {
    Bytes prevouts;
    for (const auto& in : tx.vin) serialize_outpoint(prevouts, in.prev);
    Hash256 sha_prevouts = sha256(prevouts);
    append_bytes(ss, sha_prevouts.data(), 32);

    Bytes amts;
    for (int64_t a : amounts) append_u64le(amts, uint64_t(a));
    Hash256 sha_amounts = sha256(amts);
    append_bytes(ss, sha_amounts.data(), 32);

    Bytes spks;
    for (const auto& spk : script_pubkeys) append_varbytes(spks, spk);
    Hash256 sha_spks = sha256(spks);
    append_bytes(ss, sha_spks.data(), 32);

    Bytes seqs;
    for (const auto& in : tx.vin) append_u32le(seqs, in.sequence);
    Hash256 sha_seqs = sha256(seqs);
    append_bytes(ss, sha_seqs.data(), 32);
  }

  uint8_t output_type = uint8_t(hash_type & 3);
  if (output_type != SIGHASH_NONE && output_type != SIGHASH_SINGLE) {
    Bytes outs;
    for (const auto& o : tx.vout) serialize_txout(outs, o);
    Hash256 sha_outs = sha256(outs);
    append_bytes(ss, sha_outs.data(), 32);
  } else if (output_type == SIGHASH_SINGLE && input_index < tx.vout.size()) {
    Bytes one;
    serialize_txout(one, tx.vout[input_index]);
    Hash256 sha_out = sha256(one);
    append_bytes(ss, sha_out.data(), 32);
  }

  ss.push_back(spend_type);

  if (hash_type & SIGHASH_ANYONECANPAY) {
    serialize_outpoint(ss, tx.vin[input_index].prev);
    append_u64le(ss, uint64_t(amounts[input_index]));
    append_varbytes(ss, script_pubkeys[input_index]);
    append_u32le(ss, tx.vin[input_index].sequence);
  } else {
    append_u32le(ss, uint32_t(input_index));
  }

  return tagged_hash("TapSighash", ss);
}

void sign_input_p2pkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey) {
  Bytes script_code = script_code_p2pkh(pubkey);
  Hash256 h = sighash_legacy(tx, index, script_code, SIGHASH_ALL);
  Bytes der = ecdsa_sign(priv32, h);
  der.push_back(uint8_t(SIGHASH_ALL));
  Bytes script_sig;
  append_bytes(script_sig, push_script(der));
  append_bytes(script_sig, push_script(pubkey));
  tx.vin[index].script_sig = std::move(script_sig);
  tx.vin[index].witness_stack.clear();
}

void sign_input_p2wpkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey,
                       int64_t amount) {
  Bytes script_code = script_code_p2wpkh(pubkey);
  Hash256 h = sighash_bip143(tx, index, script_code, amount, SIGHASH_ALL);
  Bytes der = ecdsa_sign(priv32, h);
  der.push_back(uint8_t(SIGHASH_ALL));
  tx.vin[index].script_sig.clear();
  tx.vin[index].witness_stack = {std::move(der), pubkey};
}

void sign_input_p2sh_p2wpkh(Transaction& tx, size_t index, const Bytes& priv32, const Bytes& pubkey,
                            int64_t amount) {
  Bytes redeem = redeem_p2sh_p2wpkh(pubkey);
  Bytes script_code = script_code_p2wpkh(pubkey);
  Hash256 h = sighash_bip143(tx, index, script_code, amount, SIGHASH_ALL);
  Bytes der = ecdsa_sign(priv32, h);
  der.push_back(uint8_t(SIGHASH_ALL));
  tx.vin[index].script_sig = push_script(redeem);
  tx.vin[index].witness_stack = {std::move(der), pubkey};
}

void sign_input_p2tr(Transaction& tx, size_t index, const Bytes& priv32,
                     const std::vector<int64_t>& amounts, const std::vector<Bytes>& spks) {
  Hash256 h = sighash_taproot_keypath(tx, index, amounts, spks, 0);
  Bytes tweaked = taproot_tweak_privkey(priv32);
  Bytes sig = schnorr_sign(tweaked, h);
  tx.vin[index].script_sig.clear();
  tx.vin[index].witness_stack = {std::move(sig)};
}

Transaction build_send(std::vector<Utxo>& utxos, const std::string& to_address, int64_t amount,
                       const std::string& change_address, int64_t fee_rate_sat_vb,
                       std::vector<size_t>& selected_indices) {
  if (amount <= 0) throw std::runtime_error("amount must be positive");
  if (fee_rate_sat_vb < 0) throw std::runtime_error("fee rate must be non-negative");

  Bytes to_spk = script_from_address(to_address);
  Bytes change_spk = script_from_address(change_address);

  selected_indices.clear();
  int64_t selected_value = 0;

  // Greedy: largest first among unspent.
  std::vector<size_t> order;
  for (size_t i = 0; i < utxos.size(); ++i) {
    if (!utxos[i].spent && utxos[i].value > 0) order.push_back(i);
  }
  std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
    return utxos[a].value > utxos[b].value;
  });

  auto estimate_fee = [&](const std::vector<size_t>& idxs, bool with_change) -> int64_t {
    size_t vsize = 10;  // version + locktime + vin/vout counts rough overhead
    for (size_t i : idxs) vsize += estimate_input_vsize(utxos[i].address_type);
    vsize += estimate_output_vsize(to_spk);
    if (with_change) vsize += estimate_output_vsize(change_spk);
    return fee_rate_sat_vb * int64_t(vsize);
  };

  for (size_t i : order) {
    selected_indices.push_back(i);
    selected_value += utxos[i].value;
    int64_t fee_no_change = estimate_fee(selected_indices, false);
    if (selected_value >= amount + fee_no_change) {
      int64_t fee_with = estimate_fee(selected_indices, true);
      int64_t change = selected_value - amount - fee_with;
      bool use_change = change >= params::kDustThreshold;
      int64_t fee = use_change ? fee_with : fee_no_change;
      if (!use_change) {
        // Recheck affordability without change (extra value goes to fee).
        if (selected_value < amount + fee_no_change) continue;
        fee = fee_no_change;
        change = 0;
      } else if (selected_value < amount + fee) {
        continue;
      }

      Transaction tx;
      tx.version = 2;
      tx.locktime = 0;
      for (size_t idx : selected_indices) {
        TxIn in;
        in.prev = utxos[idx].outpoint;
        in.sequence = 0xffffffffu;
        tx.vin.push_back(std::move(in));
      }
      TxOut out_to;
      out_to.value = amount;
      out_to.script_pubkey = to_spk;
      tx.vout.push_back(std::move(out_to));
      if (use_change) {
        TxOut out_chg;
        out_chg.value = selected_value - amount - fee;
        out_chg.script_pubkey = change_spk;
        tx.vout.push_back(std::move(out_chg));
      }
      return tx;
    }
  }
  throw std::runtime_error("insufficient funds");
}

}  // namespace ltc

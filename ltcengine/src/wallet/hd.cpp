#include "ltc/wallet/hd.hpp"
#include "ltc/crypto/base58.hpp"
#include "ltc/crypto/hash.hpp"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <cctype>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>

namespace ltc {
namespace {

constexpr uint8_t kWifVersion = 0xB0;
constexpr uint32_t kHardened = 0x80000000u;

secp256k1_context* ctx() {
  static secp256k1_context* c = nullptr;
  static std::once_flag once;
  std::call_once(once, [] {
    c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!c) throw std::runtime_error("secp256k1_context_create failed");
  });
  return c;
}

Bytes hmac_bitcoin_seed(const Bytes& seed) {
  static const char* key = "Bitcoin seed";
  return hmac_sha512(reinterpret_cast<const uint8_t*>(key), std::strlen(key), seed.data(),
                     seed.size());
}

bool seckey_valid(const Bytes& key) {
  return key.size() == 32 && secp256k1_ec_seckey_verify(ctx(), key.data()) == 1;
}

Bytes der_from_sig(const secp256k1_ecdsa_signature& sig_in) {
  secp256k1_ecdsa_signature sig = sig_in;
  secp256k1_ecdsa_signature_normalize(ctx(), &sig, &sig);
  unsigned char der[72];
  size_t der_len = sizeof(der);
  if (!secp256k1_ecdsa_signature_serialize_der(ctx(), der, &der_len, &sig))
    throw std::runtime_error("DER serialize failed");
  return Bytes(der, der + der_len);
}

uint32_t fingerprint_of_priv(const Bytes& priv32) {
  Bytes pub = priv_to_pub(priv32, true);
  Hash160 h = hash160(pub);
  return (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) | (uint32_t(h[2]) << 8) | uint32_t(h[3]);
}

}  // namespace

ExtKey master_from_seed(const Bytes& seed) {
  if (seed.size() < 16) throw std::runtime_error("seed too short");
  Bytes I = hmac_bitcoin_seed(seed);
  ExtKey out;
  out.key.assign(I.begin(), I.begin() + 32);
  out.chain.assign(I.begin() + 32, I.end());
  out.depth = 0;
  out.child = 0;
  out.parent_fp = 0;
  out.is_private = true;
  if (!seckey_valid(out.key)) throw std::runtime_error("invalid master key");
  return out;
}

ExtKey derive_child(const ExtKey& parent, uint32_t index) {
  if (parent.key.size() != 32 || parent.chain.size() != 32)
    throw std::runtime_error("invalid parent key");

  bool hardened = index >= kHardened;
  if (hardened && !parent.is_private)
    throw std::runtime_error("public derivation not supported for hardened");
  if (!parent.is_private) throw std::runtime_error("public CKD not implemented");

  Bytes data;
  if (hardened) {
    data.push_back(0x00);
    append_bytes(data, parent.key);
  } else {
    Bytes pub = priv_to_pub(parent.key, true);
    append_bytes(data, pub);
  }
  append_u8(data, uint8_t(index >> 24));
  append_u8(data, uint8_t(index >> 16));
  append_u8(data, uint8_t(index >> 8));
  append_u8(data, uint8_t(index));

  Bytes I = hmac_sha512(parent.chain, data);
  Bytes IL(I.begin(), I.begin() + 32);
  Bytes IR(I.begin() + 32, I.end());
  if (!seckey_valid(IL)) throw std::runtime_error("invalid child IL");

  Bytes child_key = parent.key;
  if (!secp256k1_ec_seckey_tweak_add(ctx(), child_key.data(), IL.data()))
    throw std::runtime_error("child key tweak failed");

  ExtKey out;
  out.key = std::move(child_key);
  out.chain = std::move(IR);
  out.depth = parent.depth + 1;
  out.child = index;
  out.parent_fp = fingerprint_of_priv(parent.key);
  out.is_private = true;
  return out;
}

ExtKey derive_path(const ExtKey& master, const std::string& path) {
  if (path.empty() || path[0] != 'm') throw std::runtime_error("path must start with m");
  ExtKey cur = master;
  size_t i = 1;
  while (i < path.size()) {
    if (path[i] != '/') throw std::runtime_error("invalid path");
    ++i;
    if (i >= path.size()) break;
    uint32_t index = 0;
    bool hardened = false;
    if (!std::isdigit(static_cast<unsigned char>(path[i])))
      throw std::runtime_error("invalid path index");
    while (i < path.size() && std::isdigit(static_cast<unsigned char>(path[i]))) {
      index = index * 10u + uint32_t(path[i] - '0');
      ++i;
    }
    if (i < path.size() && (path[i] == '\'' || path[i] == 'h' || path[i] == 'H')) {
      hardened = true;
      ++i;
    }
    if (hardened) index |= kHardened;
    cur = derive_child(cur, index);
  }
  return cur;
}

Bytes priv_to_pub(const Bytes& priv32, bool compressed) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  secp256k1_pubkey pub;
  if (!secp256k1_ec_pubkey_create(ctx(), &pub, priv32.data()))
    throw std::runtime_error("pubkey create failed");
  size_t outlen = compressed ? 33 : 65;
  Bytes out(outlen);
  unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  if (!secp256k1_ec_pubkey_serialize(ctx(), out.data(), &outlen, &pub, flags))
    throw std::runtime_error("pubkey serialize failed");
  out.resize(outlen);
  return out;
}

std::string wif_encode(const Bytes& priv32, bool compressed) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  Bytes payload;
  payload.push_back(kWifVersion);
  append_bytes(payload, priv32);
  if (compressed) payload.push_back(0x01);
  return base58check_encode(payload);
}

Bytes wif_decode(const std::string& wif, bool* compressed_out) {
  Bytes payload = base58check_decode(wif);
  if (payload.empty() || payload[0] != kWifVersion)
    throw std::runtime_error("invalid WIF version");
  bool compressed = false;
  Bytes key;
  if (payload.size() == 33) {
    key.assign(payload.begin() + 1, payload.end());
    compressed = false;
  } else if (payload.size() == 34 && payload.back() == 0x01) {
    key.assign(payload.begin() + 1, payload.end() - 1);
    compressed = true;
  } else {
    throw std::runtime_error("invalid WIF length");
  }
  if (!seckey_valid(key)) throw std::runtime_error("invalid WIF key");
  if (compressed_out) *compressed_out = compressed;
  return key;
}

Bytes ecdsa_sign(const Bytes& priv32, const Hash256& msg_hash) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_sign(ctx(), &sig, msg_hash.data(), priv32.data(), nullptr, nullptr))
    throw std::runtime_error("ecdsa_sign failed");
  return der_from_sig(sig);
}

bool ecdsa_verify(const Bytes& pub, const Hash256& msg_hash, const Bytes& der_sig) {
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx(), &pubkey, pub.data(), pub.size())) return false;
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_signature_parse_der(ctx(), &sig, der_sig.data(), der_sig.size()))
    return false;
  secp256k1_ecdsa_signature_normalize(ctx(), &sig, &sig);
  return secp256k1_ecdsa_verify(ctx(), &sig, msg_hash.data(), &pubkey) == 1;
}

Bytes xonly_pubkey(const Bytes& priv32) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx(), &keypair, priv32.data()))
    throw std::runtime_error("keypair_create failed");
  secp256k1_xonly_pubkey xonly;
  int pk_parity = 0;
  if (!secp256k1_keypair_xonly_pub(ctx(), &xonly, &pk_parity, &keypair))
    throw std::runtime_error("keypair_xonly_pub failed");
  Bytes out(32);
  if (!secp256k1_xonly_pubkey_serialize(ctx(), out.data(), &xonly))
    throw std::runtime_error("xonly serialize failed");
  return out;
}

Bytes schnorr_sign(const Bytes& priv32, const Hash256& msg_hash) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx(), &keypair, priv32.data()))
    throw std::runtime_error("keypair_create failed");
  Bytes sig(64);
  if (!secp256k1_schnorrsig_sign32(ctx(), sig.data(), msg_hash.data(), &keypair, nullptr))
    throw std::runtime_error("schnorr_sign failed");
  return sig;
}

Hash256 tagged_hash(const std::string& tag, const uint8_t* msg, size_t len) {
  Hash256 tag_hash = sha256(reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
  Bytes buf;
  buf.reserve(64 + len);
  append_bytes(buf, tag_hash.data(), 32);
  append_bytes(buf, tag_hash.data(), 32);
  append_bytes(buf, msg, len);
  return sha256(buf);
}

Hash256 tagged_hash(const std::string& tag, const Bytes& msg) {
  return tagged_hash(tag, msg.data(), msg.size());
}

Bytes taproot_tweak_privkey(const Bytes& priv32) {
  if (priv32.size() != 32) throw std::runtime_error("priv key must be 32 bytes");
  Bytes sk = priv32;
  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx(), &keypair, sk.data()))
    throw std::runtime_error("keypair_create failed");
  secp256k1_xonly_pubkey xonly;
  int parity = 0;
  if (!secp256k1_keypair_xonly_pub(ctx(), &xonly, &parity, &keypair))
    throw std::runtime_error("keypair_xonly_pub failed");
  uint8_t xonly_bytes[32];
  if (!secp256k1_xonly_pubkey_serialize(ctx(), xonly_bytes, &xonly))
    throw std::runtime_error("xonly serialize failed");
  // BIP340: if internal key has odd Y, negate secret so x-only is even-Y.
  if (parity) {
    if (!secp256k1_ec_seckey_negate(ctx(), sk.data()))
      throw std::runtime_error("seckey negate failed");
  }
  Hash256 tweak = tagged_hash("TapTweak", xonly_bytes, 32);
  if (!secp256k1_ec_seckey_tweak_add(ctx(), sk.data(), tweak.data()))
    throw std::runtime_error("taproot seckey tweak failed");
  return sk;
}

Bytes taproot_output_xonly(const Bytes& priv32) {
  return xonly_pubkey(taproot_tweak_privkey(priv32));
}

}  // namespace ltc

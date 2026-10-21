#pragma once
#include "ltc/util/bytes.hpp"
#include <array>
#include <string>

namespace ltc {

struct ExtKey {
  Bytes key;       // 32-byte priv or 33-byte pub
  Bytes chain;     // 32 bytes
  uint32_t depth = 0;
  uint32_t child = 0;
  uint32_t parent_fp = 0;
  bool is_private = true;
};

ExtKey master_from_seed(const Bytes& seed);
ExtKey derive_child(const ExtKey& parent, uint32_t index);
ExtKey derive_path(const ExtKey& master, const std::string& path);
Bytes priv_to_pub(const Bytes& priv32, bool compressed = true);
std::string wif_encode(const Bytes& priv32, bool compressed = true);
Bytes wif_decode(const std::string& wif, bool* compressed_out = nullptr);

// secp256k1 ECDSA / Schnorr helpers
Bytes ecdsa_sign(const Bytes& priv32, const Hash256& msg_hash);
bool ecdsa_verify(const Bytes& pub, const Hash256& msg_hash, const Bytes& der_sig);
Bytes schnorr_sign(const Bytes& priv32, const Hash256& msg_hash);
Bytes xonly_pubkey(const Bytes& priv32);  // 32-byte x-only (internal key)

// BIP341/BIP86: tweak private key / output x-only pubkey for key-path Taproot.
Hash256 tagged_hash(const std::string& tag, const uint8_t* msg, size_t len);
Hash256 tagged_hash(const std::string& tag, const Bytes& msg);
Bytes taproot_tweak_privkey(const Bytes& priv32);
Bytes taproot_output_xonly(const Bytes& priv32);

}  // namespace ltc

#pragma once
#include "ltc/util/bytes.hpp"
#include <string>

namespace ltc {

Bytes random_bytes(size_t n);
uint32_t random_u32();

// Minimal AES-256-CBC for wallet file encryption (PKCS7).
Bytes aes256_cbc_encrypt(const Bytes& key32, const Bytes& iv16, const Bytes& plaintext);
Bytes aes256_cbc_decrypt(const Bytes& key32, const Bytes& iv16, const Bytes& ciphertext);

}  // namespace ltc

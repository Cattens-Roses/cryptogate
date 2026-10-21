#pragma once
#include "ltc/util/bytes.hpp"

namespace ltc {

Hash256 sha256(const uint8_t* data, size_t len);
Hash256 sha256(const Bytes& data);
Hash256 double_sha256(const uint8_t* data, size_t len);
Hash256 double_sha256(const Bytes& data);
Hash160 ripemd160(const uint8_t* data, size_t len);
Hash160 hash160(const uint8_t* data, size_t len);
Hash160 hash160(const Bytes& data);
Bytes hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len);
Bytes hmac_sha512(const Bytes& key, const Bytes& data);
Bytes pbkdf2_hmac_sha512(const std::string& password, const std::string& salt, int rounds, size_t dk_len);

}  // namespace ltc

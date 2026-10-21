#include "ltc/crypto/base58.hpp"
#include "ltc/crypto/hash.hpp"
#include <algorithm>
#include <cstring>

namespace ltc {
namespace {
const char* kAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
}

std::string base58_encode(const Bytes& data) {
  size_t zeros = 0;
  while (zeros < data.size() && data[zeros] == 0) ++zeros;
  Bytes bignum(data.begin() + zeros, data.end());
  std::string encoded;
  while (!bignum.empty()) {
    int rem = 0;
    Bytes next;
    next.reserve(bignum.size());
    for (uint8_t byte : bignum) {
      int acc = rem * 256 + byte;
      int q = acc / 58;
      rem = acc % 58;
      if (!next.empty() || q) next.push_back(uint8_t(q));
    }
    encoded.push_back(kAlphabet[rem]);
    bignum = std::move(next);
  }
  encoded.append(zeros, '1');
  std::reverse(encoded.begin(), encoded.end());
  return encoded;
}

Bytes base58_decode(const std::string& s) {
  size_t zeros = 0;
  while (zeros < s.size() && s[zeros] == '1') ++zeros;
  Bytes bignum;
  for (size_t i = zeros; i < s.size(); ++i) {
    const char* p = std::strchr(kAlphabet, s[i]);
    if (!p) throw std::runtime_error("invalid base58");
    int rem = int(p - kAlphabet);
    int carry = rem;
    for (size_t j = 0; j < bignum.size(); ++j) {
      carry += int(bignum[j]) * 58;
      bignum[j] = uint8_t(carry & 0xff);
      carry >>= 8;
    }
    while (carry) {
      bignum.push_back(uint8_t(carry & 0xff));
      carry >>= 8;
    }
  }
  std::reverse(bignum.begin(), bignum.end());
  Bytes out(zeros, 0);
  out.insert(out.end(), bignum.begin(), bignum.end());
  return out;
}

std::string base58check_encode(const Bytes& payload) {
  auto checksum = double_sha256(payload);
  Bytes full = payload;
  full.insert(full.end(), checksum.begin(), checksum.begin() + 4);
  return base58_encode(full);
}

Bytes base58check_decode(const std::string& s) {
  Bytes full = base58_decode(s);
  if (full.size() < 4) throw std::runtime_error("base58check too short");
  Bytes payload(full.begin(), full.end() - 4);
  auto checksum = double_sha256(payload);
  if (!std::equal(checksum.begin(), checksum.begin() + 4, full.end() - 4))
    throw std::runtime_error("base58check checksum mismatch");
  return payload;
}

}  // namespace ltc

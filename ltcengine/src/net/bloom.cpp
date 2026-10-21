#include "ltc/net/bloom.hpp"

#include <cmath>
#include <cstring>
#include <stdexcept>

namespace ltc {
namespace net {

uint32_t BloomFilter::murmur3(const uint8_t* data, size_t len, uint32_t seed) {
  const uint32_t c1 = 0xcc9e2d51u;
  const uint32_t c2 = 0x1b873593u;
  uint32_t h1 = seed;
  const size_t nblocks = len / 4;
  for (size_t i = 0; i < nblocks; ++i) {
    uint32_t k1 = uint32_t(data[i * 4]) | (uint32_t(data[i * 4 + 1]) << 8) |
                  (uint32_t(data[i * 4 + 2]) << 16) | (uint32_t(data[i * 4 + 3]) << 24);
    k1 *= c1;
    k1 = (k1 << 15) | (k1 >> 17);
    k1 *= c2;
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >> 19);
    h1 = h1 * 5u + 0xe6546b64u;
  }
  const uint8_t* tail = data + nblocks * 4;
  uint32_t k1 = 0;
  switch (len & 3) {
    case 3:
      k1 ^= uint32_t(tail[2]) << 16;
      // fallthrough
    case 2:
      k1 ^= uint32_t(tail[1]) << 8;
      // fallthrough
    case 1:
      k1 ^= uint32_t(tail[0]);
      k1 *= c1;
      k1 = (k1 << 15) | (k1 >> 17);
      k1 *= c2;
      h1 ^= k1;
      break;
    default:
      break;
  }
  h1 ^= static_cast<uint32_t>(len);
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6bu;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35u;
  h1 ^= h1 >> 16;
  return h1;
}

BloomFilter::BloomFilter(uint32_t elements, double false_positive_rate, uint32_t tweak,
                         uint8_t flags)
    : n_tweak_(tweak), n_flags_(flags) {
  if (elements == 0) elements = 1;
  if (false_positive_rate <= 0.0 || false_positive_rate >= 1.0) false_positive_rate = 0.0001;
  double ln2 = 0.693147180559945309417;
  double n_filter =
      (-1.0 * static_cast<double>(elements) * std::log(false_positive_rate)) / (ln2 * ln2);
  uint32_t filter_bytes = static_cast<uint32_t>(n_filter / 8.0);
  if (filter_bytes > kMaxFilterBytes) filter_bytes = kMaxFilterBytes;
  if (filter_bytes == 0) filter_bytes = 1;
  filter_.assign(filter_bytes, 0);

  double n_hash =
      (static_cast<double>(filter_bytes) * 8.0) / static_cast<double>(elements) * ln2;
  n_hash_funcs_ = static_cast<uint32_t>(n_hash + 0.5);
  if (n_hash_funcs_ < 1) n_hash_funcs_ = 1;
  if (n_hash_funcs_ > kMaxHashFuncs) n_hash_funcs_ = kMaxHashFuncs;
}

void BloomFilter::insert(const uint8_t* data, size_t len) {
  if (filter_.empty() || n_hash_funcs_ == 0) return;
  uint32_t bits = static_cast<uint32_t>(filter_.size() * 8);
  for (uint32_t i = 0; i < n_hash_funcs_; ++i) {
    uint32_t idx = murmur3(data, len, i * 0xfba4c795u + n_tweak_) % bits;
    filter_[idx >> 3] |= static_cast<uint8_t>(1u << (idx & 7));
  }
}

void BloomFilter::insert(const Bytes& data) { insert(data.data(), data.size()); }

bool BloomFilter::contains(const uint8_t* data, size_t len) const {
  if (filter_.empty() || n_hash_funcs_ == 0) return false;
  uint32_t bits = static_cast<uint32_t>(filter_.size() * 8);
  for (uint32_t i = 0; i < n_hash_funcs_; ++i) {
    uint32_t idx = murmur3(data, len, i * 0xfba4c795u + n_tweak_) % bits;
    if ((filter_[idx >> 3] & static_cast<uint8_t>(1u << (idx & 7))) == 0) return false;
  }
  return true;
}

bool BloomFilter::contains(const Bytes& data) const { return contains(data.data(), data.size()); }

Bytes BloomFilter::serialize_filterload() const {
  Bytes out;
  append_varint(out, filter_.size());
  append_bytes(out, filter_);
  append_u32le(out, n_hash_funcs_);
  append_u32le(out, n_tweak_);
  append_u8(out, n_flags_);
  return out;
}

}  // namespace net
}  // namespace ltc

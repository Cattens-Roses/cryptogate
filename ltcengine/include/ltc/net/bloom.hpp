#pragma once
#include "ltc/util/bytes.hpp"

#include <cstdint>
#include <vector>

namespace ltc {
namespace net {

enum BloomFlags : uint8_t {
  BLOOM_UPDATE_NONE = 0,
  BLOOM_UPDATE_ALL = 1,
  BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
};

// BIP37 bloom filter using MurmurHash3 x86_32.
class BloomFilter {
 public:
  BloomFilter() = default;
  BloomFilter(uint32_t elements, double false_positive_rate, uint32_t tweak = 0,
              uint8_t flags = BLOOM_UPDATE_ALL);

  void insert(const uint8_t* data, size_t len);
  void insert(const Bytes& data);
  bool contains(const uint8_t* data, size_t len) const;
  bool contains(const Bytes& data) const;

  // filterload payload: nFilterBytes | filter | nHashFuncs | nTweak | nFlags
  Bytes serialize_filterload() const;

  uint32_t n_hash_funcs() const { return n_hash_funcs_; }
  uint32_t n_tweak() const { return n_tweak_; }
  uint8_t n_flags() const { return n_flags_; }
  const Bytes& filter() const { return filter_; }
  bool empty() const { return filter_.empty(); }

  static uint32_t murmur3(const uint8_t* data, size_t len, uint32_t seed);

 private:
  Bytes filter_;
  uint32_t n_hash_funcs_ = 0;
  uint32_t n_tweak_ = 0;
  uint8_t n_flags_ = BLOOM_UPDATE_ALL;

  static constexpr uint32_t kMaxFilterBytes = 36000;
  static constexpr uint32_t kMaxHashFuncs = 50;
};

}  // namespace net
}  // namespace ltc

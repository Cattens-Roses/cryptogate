#include "ltc/crypto/hash.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <string>

namespace ltc {
namespace {

constexpr uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() {
    h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    total_ = 0;
    buf_len_ = 0;
  }

  void update(const uint8_t* data, size_t len) {
    total_ += len;
    while (len > 0) {
      size_t n = std::min(len, size_t(64 - buf_len_));
      std::memcpy(buf_ + buf_len_, data, n);
      buf_len_ += n;
      data += n;
      len -= n;
      if (buf_len_ == 64) {
        transform(buf_);
        buf_len_ = 0;
      }
    }
  }

  Hash256 finalize() {
    uint64_t bit_len = total_ * 8;
    uint8_t pad[64 + 8];
    size_t pad_len = 0;
    pad[pad_len++] = 0x80;
    size_t zeros = (buf_len_ < 56) ? (56 - buf_len_ - 1) : (120 - buf_len_ - 1);
    std::memset(pad + pad_len, 0, zeros);
    pad_len += zeros;
    for (int i = 7; i >= 0; --i) pad[pad_len++] = uint8_t(bit_len >> (8 * i));
    update(pad, pad_len);
    Hash256 out{};
    for (int i = 0; i < 8; ++i) {
      out[i * 4] = uint8_t(h_[i] >> 24);
      out[i * 4 + 1] = uint8_t(h_[i] >> 16);
      out[i * 4 + 2] = uint8_t(h_[i] >> 8);
      out[i * 4 + 3] = uint8_t(h_[i]);
    }
    return out;
  }

 private:
  void transform(const uint8_t* chunk) {
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
      w[i] = (uint32_t(chunk[i * 4]) << 24) | (uint32_t(chunk[i * 4 + 1]) << 16) |
             (uint32_t(chunk[i * 4 + 2]) << 8) | uint32_t(chunk[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t t1 = h + S1 + ch + K[i] + w[i];
      uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = S0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
  }

  std::array<uint32_t, 8> h_{};
  uint64_t total_ = 0;
  uint8_t buf_[64]{};
  size_t buf_len_ = 0;
};

class Ripemd160 {
 public:
  Ripemd160() { reset(); }
  void reset() {
    h_ = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
    total_ = 0;
    buf_len_ = 0;
  }
  void update(const uint8_t* data, size_t len) {
    total_ += len;
    while (len > 0) {
      size_t n = std::min(len, size_t(64 - buf_len_));
      std::memcpy(buf_ + buf_len_, data, n);
      buf_len_ += n;
      data += n;
      len -= n;
      if (buf_len_ == 64) {
        transform(buf_);
        buf_len_ = 0;
      }
    }
  }
  Hash160 finalize() {
    uint64_t bit_len = total_ * 8;
    uint8_t pad[64 + 8];
    size_t pad_len = 0;
    pad[pad_len++] = 0x80;
    size_t zeros = (buf_len_ < 56) ? (56 - buf_len_ - 1) : (120 - buf_len_ - 1);
    std::memset(pad + pad_len, 0, zeros);
    pad_len += zeros;
    for (int i = 0; i < 8; ++i) pad[pad_len++] = uint8_t(bit_len >> (8 * i));
    update(pad, pad_len);
    Hash160 out{};
    for (int i = 0; i < 5; ++i) {
      out[i * 4] = uint8_t(h_[i]);
      out[i * 4 + 1] = uint8_t(h_[i] >> 8);
      out[i * 4 + 2] = uint8_t(h_[i] >> 16);
      out[i * 4 + 3] = uint8_t(h_[i] >> 24);
    }
    return out;
  }

 private:
  static uint32_t rol(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }
  static uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }
  static uint32_t K(int j) {
    static constexpr uint32_t k[] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
    return k[j / 16];
  }
  static uint32_t Kp(int j) {
    static constexpr uint32_t k[] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};
    return k[j / 16];
  }
  void transform(const uint8_t* chunk) {
    static constexpr int r[80] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9,
        5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8,
        12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
    static constexpr int rp[80] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8,
        12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15,
        0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
    static constexpr int s[80] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
        9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
        15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
    static constexpr int sp[80] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
        7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
        6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
    uint32_t X[16];
    for (int i = 0; i < 16; ++i)
      X[i] = uint32_t(chunk[i * 4]) | (uint32_t(chunk[i * 4 + 1]) << 8) |
             (uint32_t(chunk[i * 4 + 2]) << 16) | (uint32_t(chunk[i * 4 + 3]) << 24);
    uint32_t al = h_[0], bl = h_[1], cl = h_[2], dl = h_[3], el = h_[4];
    uint32_t ar = h_[0], br = h_[1], cr = h_[2], dr = h_[3], er = h_[4];
    for (int j = 0; j < 80; ++j) {
      uint32_t t = rol(al + f(j, bl, cl, dl) + X[r[j]] + K(j), s[j]) + el;
      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = t;
      t = rol(ar + f(79 - j, br, cr, dr) + X[rp[j]] + Kp(j), sp[j]) + er;
      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = t;
    }
    uint32_t t = h_[1] + cl + dr;
    h_[1] = h_[2] + dl + er;
    h_[2] = h_[3] + el + ar;
    h_[3] = h_[4] + al + br;
    h_[4] = h_[0] + bl + cr;
    h_[0] = t;
  }

  std::array<uint32_t, 5> h_{};
  uint64_t total_ = 0;
  uint8_t buf_[64]{};
  size_t buf_len_ = 0;
};

}  // namespace

Hash256 sha256(const uint8_t* data, size_t len) {
  Sha256 s;
  s.update(data, len);
  return s.finalize();
}
Hash256 sha256(const Bytes& data) { return sha256(data.data(), data.size()); }

Hash256 double_sha256(const uint8_t* data, size_t len) {
  auto first = sha256(data, len);
  return sha256(first.data(), first.size());
}
Hash256 double_sha256(const Bytes& data) { return double_sha256(data.data(), data.size()); }

Hash160 ripemd160(const uint8_t* data, size_t len) {
  Ripemd160 r;
  r.update(data, len);
  return r.finalize();
}

Hash160 hash160(const uint8_t* data, size_t len) {
  auto s = sha256(data, len);
  return ripemd160(s.data(), s.size());
}
Hash160 hash160(const Bytes& data) { return hash160(data.data(), data.size()); }

Bytes hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
  constexpr size_t block = 128;
  uint8_t k[block]{};
  if (key_len > block) {
    // SHA-512 of key — implement SHA-512 inline for HMAC
    // For BIP32 we only need HMAC-SHA512; implement SHA512 below.
  }
  // Full SHA-512 implementation for HMAC:
  struct Sha512 {
    std::array<uint64_t, 8> h{};
    uint64_t total = 0;
    uint8_t buf[128]{};
    size_t buf_len = 0;
    static uint64_t rotr64(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }
    void reset() {
      h = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
           0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
      total = 0;
      buf_len = 0;
    }
    void transform(const uint8_t* chunk) {
      static constexpr uint64_t K[80] = {
          0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
          0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
          0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
          0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
          0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
          0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
          0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
          0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
          0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
          0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
          0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
          0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
          0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
          0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
          0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
          0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
          0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
          0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
          0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
          0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};
      uint64_t w[80];
      for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | chunk[i * 8 + j];
      }
      for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
      }
      uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = hh + S1 + ch + K[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      }
      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
      h[4] += e;
      h[5] += f;
      h[6] += g;
      h[7] += hh;
    }
    void update(const uint8_t* data, size_t len) {
      total += len;
      while (len > 0) {
        size_t n = std::min(len, size_t(128 - buf_len));
        std::memcpy(buf + buf_len, data, n);
        buf_len += n;
        data += n;
        len -= n;
        if (buf_len == 128) {
          transform(buf);
          buf_len = 0;
        }
      }
    }
    Bytes finalize() {
      uint64_t bit_len_hi = 0;
      uint64_t bit_len_lo = total * 8;
      uint8_t pad[256];
      size_t pad_len = 0;
      pad[pad_len++] = 0x80;
      size_t zeros = (buf_len < 112) ? (112 - buf_len - 1) : (240 - buf_len - 1);
      std::memset(pad + pad_len, 0, zeros);
      pad_len += zeros;
      for (int i = 7; i >= 0; --i) pad[pad_len++] = uint8_t(bit_len_hi >> (8 * i));
      for (int i = 7; i >= 0; --i) pad[pad_len++] = uint8_t(bit_len_lo >> (8 * i));
      update(pad, pad_len);
      Bytes out(64);
      for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) out[i * 8 + j] = uint8_t(h[i] >> (56 - 8 * j));
      return out;
    }
  };

  auto sha512 = [](const uint8_t* d, size_t n) {
    Sha512 s;
    s.reset();
    s.update(d, n);
    return s.finalize();
  };

  Bytes key_block(block, 0);
  if (key_len > block) {
    auto hashed = sha512(key, key_len);
    std::memcpy(key_block.data(), hashed.data(), hashed.size());
  } else {
    std::memcpy(key_block.data(), key, key_len);
  }

  Bytes ipad(block), opad(block);
  for (size_t i = 0; i < block; ++i) {
    ipad[i] = key_block[i] ^ 0x36;
    opad[i] = key_block[i] ^ 0x5c;
  }
  Sha512 inner;
  inner.reset();
  inner.update(ipad.data(), ipad.size());
  inner.update(data, data_len);
  auto inner_hash = inner.finalize();
  Sha512 outer;
  outer.reset();
  outer.update(opad.data(), opad.size());
  outer.update(inner_hash.data(), inner_hash.size());
  return outer.finalize();
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data) {
  return hmac_sha512(key.data(), key.size(), data.data(), data.size());
}

Bytes pbkdf2_hmac_sha512(const std::string& password, const std::string& salt, int rounds,
                         size_t dk_len) {
  Bytes out(dk_len);
  size_t offset = 0;
  uint32_t block_index = 1;
  while (offset < dk_len) {
    Bytes msg(salt.begin(), salt.end());
    append_u8(msg, uint8_t(block_index >> 24));
    append_u8(msg, uint8_t(block_index >> 16));
    append_u8(msg, uint8_t(block_index >> 8));
    append_u8(msg, uint8_t(block_index));
    Bytes u = hmac_sha512(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                          msg.data(), msg.size());
    Bytes t = u;
    for (int i = 1; i < rounds; ++i) {
      u = hmac_sha512(reinterpret_cast<const uint8_t*>(password.data()), password.size(), u.data(),
                      u.size());
      for (size_t j = 0; j < t.size(); ++j) t[j] ^= u[j];
    }
    size_t n = std::min(t.size(), dk_len - offset);
    std::memcpy(out.data() + offset, t.data(), n);
    offset += n;
    ++block_index;
  }
  return out;
}

}  // namespace ltc

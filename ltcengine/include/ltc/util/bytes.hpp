#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ltc {

using Bytes = std::vector<uint8_t>;

inline void append_u8(Bytes& out, uint8_t v) { out.push_back(v); }
inline void append_u16le(Bytes& out, uint16_t v) {
  out.push_back(uint8_t(v));
  out.push_back(uint8_t(v >> 8));
}
inline void append_u32le(Bytes& out, uint32_t v) {
  out.push_back(uint8_t(v));
  out.push_back(uint8_t(v >> 8));
  out.push_back(uint8_t(v >> 16));
  out.push_back(uint8_t(v >> 24));
}
inline void append_u64le(Bytes& out, uint64_t v) {
  for (int i = 0; i < 8; ++i) out.push_back(uint8_t(v >> (8 * i)));
}
inline void append_bytes(Bytes& out, const Bytes& b) {
  out.insert(out.end(), b.begin(), b.end());
}
inline void append_bytes(Bytes& out, const uint8_t* p, size_t n) {
  out.insert(out.end(), p, p + n);
}

inline uint16_t read_u16le(const uint8_t* p) {
  return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t read_u32le(const uint8_t* p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t read_u64le(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
  return v;
}

inline void append_varint(Bytes& out, uint64_t v) {
  if (v < 0xfd) {
    append_u8(out, uint8_t(v));
  } else if (v <= 0xffff) {
    append_u8(out, 0xfd);
    append_u16le(out, uint16_t(v));
  } else if (v <= 0xffffffffull) {
    append_u8(out, 0xfe);
    append_u32le(out, uint32_t(v));
  } else {
    append_u8(out, 0xff);
    append_u64le(out, v);
  }
}

inline uint64_t read_varint(const uint8_t*& p, const uint8_t* end) {
  if (p >= end) throw std::runtime_error("varint overflow");
  uint8_t prefix = *p++;
  if (prefix < 0xfd) return prefix;
  if (prefix == 0xfd) {
    if (p + 2 > end) throw std::runtime_error("varint overflow");
    uint16_t v = read_u16le(p);
    p += 2;
    return v;
  }
  if (prefix == 0xfe) {
    if (p + 4 > end) throw std::runtime_error("varint overflow");
    uint32_t v = read_u32le(p);
    p += 4;
    return v;
  }
  if (p + 8 > end) throw std::runtime_error("varint overflow");
  uint64_t v = read_u64le(p);
  p += 8;
  return v;
}

inline void append_varbytes(Bytes& out, const Bytes& b) {
  append_varint(out, b.size());
  append_bytes(out, b);
}

inline Bytes read_varbytes(const uint8_t*& p, const uint8_t* end) {
  uint64_t n = read_varint(p, end);
  if (p + n > end) throw std::runtime_error("varbytes overflow");
  Bytes out(p, p + n);
  p += n;
  return out;
}

inline std::string to_hex(const uint8_t* p, size_t n, bool reverse = false) {
  static const char* hex = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    uint8_t b = reverse ? p[n - 1 - i] : p[i];
    s[i * 2] = hex[b >> 4];
    s[i * 2 + 1] = hex[b & 0xf];
  }
  return s;
}

inline std::string to_hex(const Bytes& b, bool reverse = false) {
  return to_hex(b.data(), b.size(), reverse);
}

inline Bytes from_hex(const std::string& hex) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("invalid hex");
  };
  if (hex.size() % 2) throw std::runtime_error("invalid hex length");
  Bytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i)
    out[i] = uint8_t((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
  return out;
}

inline Bytes reverse_bytes(Bytes b) {
  std::reverse(b.begin(), b.end());
  return b;
}

template <size_t N>
using Hash = std::array<uint8_t, N>;
using Hash256 = Hash<32>;
using Hash160 = Hash<20>;

}  // namespace ltc

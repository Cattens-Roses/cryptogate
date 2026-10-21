#include "ltc/net/serialize.hpp"

#include "ltc/crypto/hash.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace ltc {
namespace net {
namespace {

void write_hash(Bytes& out, const Hash256& h) { append_bytes(out, h.data(), h.size()); }

Hash256 read_hash(const uint8_t*& p, const uint8_t* end) {
  if (p + 32 > end) throw std::runtime_error("hash underflow");
  Hash256 h{};
  std::memcpy(h.data(), p, 32);
  p += 32;
  return h;
}

void append_locator(Bytes& out, uint32_t version, const std::vector<Hash256>& locator,
                    const Hash256& stop) {
  append_u32le(out, version);
  append_varint(out, locator.size());
  for (const auto& h : locator) write_hash(out, h);
  write_hash(out, stop);
}

}  // namespace

Hash256 payload_checksum(const Bytes& payload) {
  return double_sha256(payload.empty() ? nullptr : payload.data(), payload.size());
}

void command_to_bytes(const std::string& command, uint8_t out[kCommandSize]) {
  std::memset(out, 0, kCommandSize);
  size_t n = std::min(command.size(), kCommandSize);
  std::memcpy(out, command.data(), n);
}

std::string command_from_bytes(const uint8_t cmd[kCommandSize]) {
  size_t n = 0;
  while (n < kCommandSize && cmd[n] != 0) ++n;
  return std::string(reinterpret_cast<const char*>(cmd), n);
}

Bytes encode_message(const std::string& command, const Bytes& payload, uint32_t magic) {
  if (payload.size() > kMaxPayload) throw std::runtime_error("payload too large");
  Bytes out;
  out.reserve(kHeaderSize + payload.size());
  append_u32le(out, magic);
  uint8_t cmd[kCommandSize];
  command_to_bytes(command, cmd);
  append_bytes(out, cmd, kCommandSize);
  append_u32le(out, static_cast<uint32_t>(payload.size()));
  Hash256 cs = payload_checksum(payload);
  append_bytes(out, cs.data(), 4);
  append_bytes(out, payload);
  return out;
}

size_t try_decode_message(const uint8_t* data, size_t len, NetMessage& out, uint32_t magic) {
  if (len < kHeaderSize) return 0;
  uint32_t mag = read_u32le(data);
  if (mag != magic) throw std::runtime_error("bad network magic");
  std::string cmd = command_from_bytes(data + 4);
  uint32_t plen = read_u32le(data + 16);
  if (plen > kMaxPayload) throw std::runtime_error("payload length exceeds limit");
  if (len < kHeaderSize + plen) return 0;
  const uint8_t* csum = data + 20;
  Bytes payload(data + kHeaderSize, data + kHeaderSize + plen);
  Hash256 expect = payload_checksum(payload);
  if (std::memcmp(csum, expect.data(), 4) != 0) throw std::runtime_error("bad message checksum");
  out.command = std::move(cmd);
  out.payload = std::move(payload);
  return kHeaderSize + plen;
}

Hash256 BlockHeader::hash() const {
  Bytes raw = serialize();
  return double_sha256(raw);
}

Bytes BlockHeader::serialize() const {
  Bytes out;
  out.reserve(80);
  append_u32le(out, static_cast<uint32_t>(version));
  write_hash(out, prev);
  write_hash(out, merkle_root);
  append_u32le(out, timestamp);
  append_u32le(out, bits);
  append_u32le(out, nonce);
  return out;
}

BlockHeader BlockHeader::deserialize(const uint8_t* p, const uint8_t* end) {
  if (p + 80 > end) throw std::runtime_error("header underflow");
  BlockHeader h;
  h.version = static_cast<int32_t>(read_u32le(p));
  p += 4;
  h.prev = read_hash(p, end);
  h.merkle_root = read_hash(p, end);
  h.timestamp = read_u32le(p);
  p += 4;
  h.bits = read_u32le(p);
  p += 4;
  h.nonce = read_u32le(p);
  return h;
}

Bytes encode_version(uint32_t version, uint64_t services, int64_t timestamp, uint64_t nonce,
                     const std::string& user_agent, int32_t start_height, bool relay) {
  // Prefer IPv4 port in network byte order inside version (unused by most peers, keep correct).
  auto append_net_addr = [](Bytes& out, uint64_t services, uint8_t a, uint8_t b, uint8_t c,
                            uint8_t d, uint16_t port) {
    append_u64le(out, services);
    out.insert(out.end(), 10, 0);
    out.push_back(0xff);
    out.push_back(0xff);
    out.push_back(a);
    out.push_back(b);
    out.push_back(c);
    out.push_back(d);
    out.push_back(uint8_t(port >> 8));
    out.push_back(uint8_t(port & 0xff));
  };
  Bytes out;
  append_u32le(out, version);
  append_u64le(out, services);
  append_u64le(out, static_cast<uint64_t>(timestamp));
  append_net_addr(out, 1, 127, 0, 0, 1, 9333);
  append_net_addr(out, services, 0, 0, 0, 0, 9333);
  append_u64le(out, nonce);
  Bytes ua(user_agent.begin(), user_agent.end());
  append_varbytes(out, ua);
  append_u32le(out, static_cast<uint32_t>(start_height));
  if (version >= 70001) append_u8(out, relay ? 1 : 0);
  return out;
}

bool decode_version(const Bytes& payload, uint32_t& version, uint64_t& services, int64_t& timestamp,
                    uint64_t& nonce, std::string& user_agent, int32_t& start_height, bool& relay) {
  const uint8_t* p = payload.data();
  const uint8_t* end = p + payload.size();
  if (p + 4 + 8 + 8 + 26 + 26 + 8 > end) return false;
  version = read_u32le(p);
  p += 4;
  services = read_u64le(p);
  p += 8;
  timestamp = static_cast<int64_t>(read_u64le(p));
  p += 8;
  p += 26;  // addr_recv
  p += 26;  // addr_from
  nonce = read_u64le(p);
  p += 8;
  Bytes ua = read_varbytes(p, end);
  user_agent.assign(ua.begin(), ua.end());
  if (p + 4 > end) return false;
  start_height = static_cast<int32_t>(read_u32le(p));
  p += 4;
  relay = true;
  if (p < end) relay = (*p != 0);
  return true;
}

Bytes encode_ping(uint64_t nonce) {
  Bytes out;
  append_u64le(out, nonce);
  return out;
}

Bytes encode_pong(uint64_t nonce) { return encode_ping(nonce); }

uint64_t decode_nonce64(const Bytes& payload) {
  if (payload.size() < 8) throw std::runtime_error("nonce underflow");
  return read_u64le(payload.data());
}

Bytes encode_getheaders(uint32_t version, const std::vector<Hash256>& locator,
                        const Hash256& stop) {
  Bytes out;
  append_locator(out, version, locator, stop);
  return out;
}

Bytes encode_getblocks(uint32_t version, const std::vector<Hash256>& locator,
                       const Hash256& stop) {
  Bytes out;
  append_locator(out, version, locator, stop);
  return out;
}

std::vector<BlockHeader> decode_headers(const Bytes& payload) {
  const uint8_t* p = payload.data();
  const uint8_t* end = p + payload.size();
  uint64_t count = read_varint(p, end);
  std::vector<BlockHeader> headers;
  headers.reserve(static_cast<size_t>(count));
  for (uint64_t i = 0; i < count; ++i) {
    headers.push_back(BlockHeader::deserialize(p, end));
    p += 80;
    // tx count varint (always 0 for headers message)
    (void)read_varint(p, end);
  }
  return headers;
}

Bytes encode_inv(const std::vector<InvVector>& items) {
  Bytes out;
  append_varint(out, items.size());
  for (const auto& it : items) {
    append_u32le(out, static_cast<uint32_t>(it.type));
    write_hash(out, it.hash);
  }
  return out;
}

Bytes encode_getdata(const std::vector<InvVector>& items) { return encode_inv(items); }

std::vector<InvVector> decode_inv(const Bytes& payload) {
  const uint8_t* p = payload.data();
  const uint8_t* end = p + payload.size();
  uint64_t count = read_varint(p, end);
  std::vector<InvVector> items;
  items.reserve(static_cast<size_t>(count));
  for (uint64_t i = 0; i < count; ++i) {
    if (p + 36 > end) throw std::runtime_error("inv underflow");
    InvVector v;
    v.type = static_cast<InvType>(read_u32le(p));
    p += 4;
    v.hash = read_hash(p, end);
    items.push_back(v);
  }
  return items;
}

Bytes encode_addr_ipv4(uint32_t ipv4_be, uint16_t port, uint64_t services) {
  Bytes out;
  append_u64le(out, services);
  out.insert(out.end(), 10, 0);
  out.push_back(0xff);
  out.push_back(0xff);
  out.push_back(uint8_t((ipv4_be >> 24) & 0xff));
  out.push_back(uint8_t((ipv4_be >> 16) & 0xff));
  out.push_back(uint8_t((ipv4_be >> 8) & 0xff));
  out.push_back(uint8_t(ipv4_be & 0xff));
  // port is network byte order in addr
  out.push_back(uint8_t((port >> 8) & 0xff));
  out.push_back(uint8_t(port & 0xff));
  return out;
}

}  // namespace net
}  // namespace ltc

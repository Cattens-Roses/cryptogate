#pragma once
#include "ltc/params.hpp"
#include "ltc/util/bytes.hpp"

#include <string>
#include <vector>

namespace ltc {
namespace net {

inline constexpr size_t kCommandSize = 12;
inline constexpr size_t kHeaderSize = 24;  // magic + command + length + checksum
inline constexpr uint32_t kMaxPayload = 32 * 1024 * 1024;

struct NetMessage {
  std::string command;  // trimmed ASCII
  Bytes payload;
};

// Frame a payload into a Litecoin P2P message (wire magic fb c0 b6 db).
Bytes encode_message(const std::string& command, const Bytes& payload,
                     uint32_t magic = params::kMagicMainnet);

// Parse one complete message from buffer; returns bytes consumed, or 0 if incomplete.
// Throws on corrupt framing/checksum.
size_t try_decode_message(const uint8_t* data, size_t len, NetMessage& out,
                          uint32_t magic = params::kMagicMainnet);

Hash256 payload_checksum(const Bytes& payload);
std::string command_from_bytes(const uint8_t cmd[kCommandSize]);
void command_to_bytes(const std::string& command, uint8_t out[kCommandSize]);

// --- Common payload helpers ---

struct NetworkAddress {
  uint64_t services = 0;
  Bytes ip;  // 16 bytes IPv6-mapped
  uint16_t port = 0;
};

Bytes encode_version(uint32_t version, uint64_t services, int64_t timestamp, uint64_t nonce,
                     const std::string& user_agent, int32_t start_height, bool relay = true);
bool decode_version(const Bytes& payload, uint32_t& version, uint64_t& services, int64_t& timestamp,
                    uint64_t& nonce, std::string& user_agent, int32_t& start_height, bool& relay);

Bytes encode_ping(uint64_t nonce);
Bytes encode_pong(uint64_t nonce);
uint64_t decode_nonce64(const Bytes& payload);

Bytes encode_getheaders(uint32_t version, const std::vector<Hash256>& locator,
                        const Hash256& stop = Hash256{});
Bytes encode_getblocks(uint32_t version, const std::vector<Hash256>& locator,
                       const Hash256& stop = Hash256{});

struct BlockHeader {
  int32_t version = 0;
  Hash256 prev{};
  Hash256 merkle_root{};
  uint32_t timestamp = 0;
  uint32_t bits = 0;
  uint32_t nonce = 0;

  Hash256 hash() const;
  Bytes serialize() const;
  static BlockHeader deserialize(const uint8_t* p, const uint8_t* end);
};

std::vector<BlockHeader> decode_headers(const Bytes& payload);

enum class InvType : uint32_t {
  Error = 0,
  Tx = 1,
  Block = 2,
  FilteredBlock = 3,
  CompactBlock = 4,
  WitnessTx = 0x40000001u,
  WitnessBlock = 0x40000002u,
  FilteredWitnessBlock = 0x40000003u,
};

struct InvVector {
  InvType type = InvType::Error;
  Hash256 hash{};
};

Bytes encode_inv(const std::vector<InvVector>& items);
Bytes encode_getdata(const std::vector<InvVector>& items);
std::vector<InvVector> decode_inv(const Bytes& payload);

Bytes encode_addr_ipv4(uint32_t ipv4_be, uint16_t port, uint64_t services = 1);

}  // namespace net
}  // namespace ltc

#pragma once
#include <cstdint>
#include <string>

namespace ltc {
namespace params {

inline constexpr uint32_t kMagicMainnet = 0xdbb6c0fb;  // wire bytes: fb c0 b6 db

inline constexpr uint16_t kDefaultPort = 9333;
inline constexpr uint8_t kP2PKHVersion = 48;  // L...
inline constexpr uint8_t kP2SHVersion = 50;   // M...
inline constexpr const char* kBech32HRP = "ltc";
inline constexpr uint32_t kProtocolVersion = 70015;
inline constexpr uint64_t kServices = 1;  // NODE_NETWORK
inline constexpr uint64_t kNodeNetwork = 1;
inline constexpr uint64_t kNodeBloom = 4;
inline constexpr uint64_t kNodeWitness = 8;
inline constexpr uint32_t kBip44CoinType = 2;

// Litecoin genesis hash (internal byte order / display reversed hex):
// 12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2
inline const char* kGenesisHashHex =
    "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2";

inline const char* kDnsSeeds[] = {
    "dnsseed.litecointools.com",
    "seed-a.litecoin.loshan.co.uk",
    "dnsseed.thrasher.io",
    "dnsseed.litecoinpool.org",
    "seed.ltc.xurious.com",
    nullptr,
};

inline constexpr int64_t kDustThreshold = 546;
inline constexpr int64_t kDefaultFeeRateSatPerVb = 10;  // sats/vbyte

}  // namespace params
}  // namespace ltc

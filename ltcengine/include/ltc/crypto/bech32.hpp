#pragma once
#include "ltc/util/bytes.hpp"
#include <string>
#include <utility>

namespace ltc {

enum class Bech32Variant { Bech32, Bech32m };

std::string bech32_encode(const std::string& hrp, int witver, const Bytes& witprog,
                          Bech32Variant variant);
// Returns {witver, program}
std::pair<int, Bytes> bech32_decode(const std::string& addr, std::string* hrp_out = nullptr);

}  // namespace ltc

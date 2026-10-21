#pragma once
#include "ltc/util/bytes.hpp"
#include <string>

namespace ltc {

std::string base58_encode(const Bytes& data);
Bytes base58_decode(const std::string& s);
std::string base58check_encode(const Bytes& payload);
Bytes base58check_decode(const std::string& s);

}  // namespace ltc

#pragma once
#include "ltc/util/bytes.hpp"
#include <string>
#include <vector>

namespace ltc {

std::string generate_mnemonic(int strength_bits = 128);
Bytes mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase = "");
bool mnemonic_is_valid(const std::string& mnemonic);

}  // namespace ltc

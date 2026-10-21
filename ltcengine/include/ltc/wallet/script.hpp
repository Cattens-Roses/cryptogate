#pragma once
#include "ltc/util/bytes.hpp"
#include <string>

namespace ltc {

enum class AddressType {
  P2PKH,    // legacy L...
  P2SH,     // M... (also accepts 3...)
  P2WPKH,   // ltc1q... 20-byte
  P2WSH,    // ltc1q... 32-byte
  P2TR,     // ltc1p... taproot
  Unknown
};

struct DecodedAddress {
  AddressType type = AddressType::Unknown;
  Bytes script_pubkey;
  Bytes payload;  // hash / program
  int witness_version = -1;
};

Bytes script_p2pkh(const Hash160& h160);
Bytes script_p2sh(const Hash160& h160);
Bytes script_p2wpkh(const Hash160& h160);
Bytes script_p2wsh(const Hash256& h256);
Bytes script_p2tr(const Bytes& xonly32);
Bytes script_from_address(const std::string& address);
DecodedAddress decode_address(const std::string& address);

std::string address_p2pkh(const Hash160& h160);
std::string address_p2sh(const Hash160& h160);
std::string address_p2wpkh(const Hash160& h160);
std::string address_p2wsh(const Hash256& h256);
std::string address_p2tr(const Bytes& xonly32);

std::string encode_address(AddressType type, const Bytes& payload);
const char* address_type_name(AddressType t);

}  // namespace ltc

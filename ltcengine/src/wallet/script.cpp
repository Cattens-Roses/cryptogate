#include "ltc/wallet/script.hpp"
#include "ltc/crypto/base58.hpp"
#include "ltc/crypto/bech32.hpp"
#include "ltc/params.hpp"
#include <cstring>
#include <stdexcept>

namespace ltc {
namespace {

constexpr uint8_t OP_0 = 0x00;
constexpr uint8_t OP_1 = 0x51;
constexpr uint8_t OP_DUP = 0x76;
constexpr uint8_t OP_EQUAL = 0x87;
constexpr uint8_t OP_EQUALVERIFY = 0x88;
constexpr uint8_t OP_HASH160 = 0xa9;
constexpr uint8_t OP_CHECKSIG = 0xac;

}  // namespace

Bytes script_p2pkh(const Hash160& h160) {
  Bytes s;
  s.push_back(OP_DUP);
  s.push_back(OP_HASH160);
  s.push_back(0x14);
  append_bytes(s, h160.data(), h160.size());
  s.push_back(OP_EQUALVERIFY);
  s.push_back(OP_CHECKSIG);
  return s;
}

Bytes script_p2sh(const Hash160& h160) {
  Bytes s;
  s.push_back(OP_HASH160);
  s.push_back(0x14);
  append_bytes(s, h160.data(), h160.size());
  s.push_back(OP_EQUAL);
  return s;
}

Bytes script_p2wpkh(const Hash160& h160) {
  Bytes s;
  s.push_back(OP_0);
  s.push_back(0x14);
  append_bytes(s, h160.data(), h160.size());
  return s;
}

Bytes script_p2wsh(const Hash256& h256) {
  Bytes s;
  s.push_back(OP_0);
  s.push_back(0x20);
  append_bytes(s, h256.data(), h256.size());
  return s;
}

Bytes script_p2tr(const Bytes& xonly32) {
  if (xonly32.size() != 32) throw std::runtime_error("taproot xonly must be 32 bytes");
  Bytes s;
  s.push_back(OP_1);
  s.push_back(0x20);
  append_bytes(s, xonly32);
  return s;
}

std::string address_p2pkh(const Hash160& h160) {
  Bytes payload;
  payload.push_back(params::kP2PKHVersion);
  append_bytes(payload, h160.data(), h160.size());
  return base58check_encode(payload);
}

std::string address_p2sh(const Hash160& h160) {
  Bytes payload;
  payload.push_back(params::kP2SHVersion);
  append_bytes(payload, h160.data(), h160.size());
  return base58check_encode(payload);
}

std::string address_p2wpkh(const Hash160& h160) {
  Bytes prog(h160.begin(), h160.end());
  return bech32_encode(params::kBech32HRP, 0, prog, Bech32Variant::Bech32);
}

std::string address_p2wsh(const Hash256& h256) {
  Bytes prog(h256.begin(), h256.end());
  return bech32_encode(params::kBech32HRP, 0, prog, Bech32Variant::Bech32);
}

std::string address_p2tr(const Bytes& xonly32) {
  if (xonly32.size() != 32) throw std::runtime_error("taproot xonly must be 32 bytes");
  return bech32_encode(params::kBech32HRP, 1, xonly32, Bech32Variant::Bech32m);
}

std::string encode_address(AddressType type, const Bytes& payload) {
  switch (type) {
    case AddressType::P2PKH: {
      if (payload.size() != 20) throw std::runtime_error("P2PKH payload must be 20 bytes");
      Hash160 h{};
      std::memcpy(h.data(), payload.data(), 20);
      return address_p2pkh(h);
    }
    case AddressType::P2SH: {
      if (payload.size() != 20) throw std::runtime_error("P2SH payload must be 20 bytes");
      Hash160 h{};
      std::memcpy(h.data(), payload.data(), 20);
      return address_p2sh(h);
    }
    case AddressType::P2WPKH: {
      if (payload.size() != 20) throw std::runtime_error("P2WPKH payload must be 20 bytes");
      Hash160 h{};
      std::memcpy(h.data(), payload.data(), 20);
      return address_p2wpkh(h);
    }
    case AddressType::P2WSH: {
      if (payload.size() != 32) throw std::runtime_error("P2WSH payload must be 32 bytes");
      Hash256 h{};
      std::memcpy(h.data(), payload.data(), 32);
      return address_p2wsh(h);
    }
    case AddressType::P2TR:
      return address_p2tr(payload);
    default:
      throw std::runtime_error("unknown address type");
  }
}

const char* address_type_name(AddressType t) {
  switch (t) {
    case AddressType::P2PKH:
      return "p2pkh";
    case AddressType::P2SH:
      return "p2sh";
    case AddressType::P2WPKH:
      return "p2wpkh";
    case AddressType::P2WSH:
      return "p2wsh";
    case AddressType::P2TR:
      return "p2tr";
    default:
      return "unknown";
  }
}

DecodedAddress decode_address(const std::string& address) {
  DecodedAddress out;
  if (address.size() >= 4 &&
      (address[0] == 'l' || address[0] == 'L') &&
      (address[1] == 't' || address[1] == 'T') &&
      (address[2] == 'c' || address[2] == 'C') && address[3] == '1') {
    std::string hrp;
    auto decoded = bech32_decode(address, &hrp);
    if (hrp != params::kBech32HRP && hrp != "LTC")
      throw std::runtime_error("unexpected bech32 HRP");
    out.witness_version = decoded.first;
    out.payload = std::move(decoded.second);
    if (out.witness_version == 0) {
      if (out.payload.size() == 20) {
        out.type = AddressType::P2WPKH;
        Hash160 h{};
        std::memcpy(h.data(), out.payload.data(), 20);
        out.script_pubkey = script_p2wpkh(h);
      } else if (out.payload.size() == 32) {
        out.type = AddressType::P2WSH;
        Hash256 h{};
        std::memcpy(h.data(), out.payload.data(), 32);
        out.script_pubkey = script_p2wsh(h);
      } else {
        throw std::runtime_error("invalid v0 witness program length");
      }
    } else if (out.witness_version == 1 && out.payload.size() == 32) {
      out.type = AddressType::P2TR;
      out.script_pubkey = script_p2tr(out.payload);
    } else {
      throw std::runtime_error("unsupported witness version");
    }
    return out;
  }

  Bytes payload = base58check_decode(address);
  if (payload.size() != 21) throw std::runtime_error("invalid base58 address length");
  uint8_t ver = payload[0];
  out.payload.assign(payload.begin() + 1, payload.end());
  Hash160 h{};
  std::memcpy(h.data(), out.payload.data(), 20);
  if (ver == params::kP2PKHVersion) {
    out.type = AddressType::P2PKH;
    out.script_pubkey = script_p2pkh(h);
  } else if (ver == params::kP2SHVersion || ver == 5) {
    // Litecoin M... (50) and legacy Bitcoin-style 3... (version 5) P2SH.
    out.type = AddressType::P2SH;
    out.script_pubkey = script_p2sh(h);
  } else {
    throw std::runtime_error("unknown address version");
  }
  return out;
}

Bytes script_from_address(const std::string& address) {
  return decode_address(address).script_pubkey;
}

}  // namespace ltc

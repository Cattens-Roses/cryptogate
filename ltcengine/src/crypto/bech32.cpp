#include "ltc/crypto/bech32.hpp"
#include <cctype>

namespace ltc {
namespace {

const char* kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t polymod(const std::vector<uint8_t>& values) {
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint8_t top = chk >> 25;
    chk = ((chk & 0x1ffffffu) << 5) ^ v;
    if (top & 1) chk ^= 0x3b6a57b2;
    if (top & 2) chk ^= 0x26508e6d;
    if (top & 4) chk ^= 0x1ea119fa;
    if (top & 8) chk ^= 0x3d4233dd;
    if (top & 16) chk ^= 0x2a1462b3;
  }
  return chk;
}

std::vector<uint8_t> hrp_expand(const std::string& hrp) {
  std::vector<uint8_t> ret;
  for (char c : hrp) ret.push_back(uint8_t(c >> 5));
  ret.push_back(0);
  for (char c : hrp) ret.push_back(uint8_t(c & 31));
  return ret;
}

uint32_t encoding_const(Bech32Variant v) { return v == Bech32Variant::Bech32m ? 0x2bc830a3u : 1u; }

bool convert_bits(const std::vector<uint8_t>& in, int frombits, int tobits, bool pad,
                  std::vector<uint8_t>& out) {
  uint32_t acc = 0;
  int bits = 0;
  uint32_t maxv = (1u << tobits) - 1;
  for (uint8_t value : in) {
    if ((value >> frombits) != 0) return false;
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      out.push_back(uint8_t((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits) out.push_back(uint8_t((acc << (tobits - bits)) & maxv));
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return false;
  }
  return true;
}

}  // namespace

std::string bech32_encode(const std::string& hrp, int witver, const Bytes& witprog,
                          Bech32Variant variant) {
  std::vector<uint8_t> data;
  data.push_back(uint8_t(witver));
  std::vector<uint8_t> prog(witprog.begin(), witprog.end());
  if (!convert_bits(prog, 8, 5, true, data)) throw std::runtime_error("bech32 convert_bits failed");
  auto values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  for (int i = 0; i < 6; ++i) values.push_back(0);
  uint32_t mod = polymod(values) ^ encoding_const(variant);
  for (int i = 0; i < 6; ++i) data.push_back(uint8_t((mod >> (5 * (5 - i))) & 31));
  std::string out = hrp + '1';
  for (uint8_t d : data) out.push_back(kCharset[d]);
  return out;
}

std::pair<int, Bytes> bech32_decode(const std::string& addr, std::string* hrp_out) {
  if (addr.size() < 8 || addr.size() > 90) throw std::runtime_error("invalid bech32 length");
  bool lower = false, upper = false;
  for (char c : addr) {
    if (c >= 'a' && c <= 'z') lower = true;
    else if (c >= 'A' && c <= 'Z') upper = true;
    else if (c < 33 || c > 126) throw std::runtime_error("invalid bech32 char");
  }
  if (lower && upper) throw std::runtime_error("mixed case bech32");
  std::string s = addr;
  for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
  auto pos = s.rfind('1');
  if (pos == std::string::npos || pos == 0 || pos + 7 > s.size())
    throw std::runtime_error("invalid bech32 separator");
  std::string hrp = s.substr(0, pos);
  std::string data_part = s.substr(pos + 1);
  std::vector<uint8_t> data;
  data.reserve(data_part.size());
  for (char c : data_part) {
    const char* p = std::strchr(kCharset, c);
    if (!p) throw std::runtime_error("invalid bech32 data");
    data.push_back(uint8_t(p - kCharset));
  }
  auto values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  uint32_t pm = polymod(values);
  Bech32Variant variant;
  if (pm == encoding_const(Bech32Variant::Bech32)) variant = Bech32Variant::Bech32;
  else if (pm == encoding_const(Bech32Variant::Bech32m)) variant = Bech32Variant::Bech32m;
  else throw std::runtime_error("bech32 checksum failed");
  if (data.size() < 7) throw std::runtime_error("bech32 data too short");
  int witver = data[0];
  std::vector<uint8_t> prog5(data.begin() + 1, data.end() - 6);
  Bytes prog;
  if (!convert_bits(prog5, 5, 8, false, prog)) throw std::runtime_error("bech32 program bits");
  if (witver > 16) throw std::runtime_error("invalid witness version");
  if (prog.size() < 2 || prog.size() > 40) throw std::runtime_error("invalid witness program length");
  if (witver == 0) {
    if (variant != Bech32Variant::Bech32) throw std::runtime_error("v0 must be bech32");
    if (prog.size() != 20 && prog.size() != 32) throw std::runtime_error("invalid v0 program");
  } else {
    if (variant != Bech32Variant::Bech32m) throw std::runtime_error("v1+ must be bech32m");
  }
  if (hrp_out) *hrp_out = hrp;
  return {witver, prog};
}

}  // namespace ltc

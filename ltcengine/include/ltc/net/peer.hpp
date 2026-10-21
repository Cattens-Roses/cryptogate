#pragma once
#include "ltc/net/serialize.hpp"
#include "ltc/util/bytes.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace ltc {
namespace net {

class Peer {
 public:
  Peer();
  ~Peer();

  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  // Resolve DNS and connect TCP to host:port (default Litecoin 9333).
  // timeout_ms bounds the non-blocking connect wait (default 1s).
  // If cancel is set, aborts early so parallel dials can stop quickly.
  void connect(const std::string& host, uint16_t port = 9333, int timeout_ms = 1000,
               std::atomic<bool>* cancel = nullptr);
  void disconnect();
  bool connected() const { return sock_valid_; }
  const std::string& remote_host() const { return remote_host_; }

  void send_message(const std::string& command, const Bytes& payload = {});
  // Blocking read of one framed message (uses internal buffer).
  NetMessage receive_message(int timeout_ms = 60000);

  // Send version + wait for version/verack; reply verack.
  void handshake(int32_t start_height = 0, const std::string& user_agent = "/ltcengine:1.0.0/",
                  std::atomic<bool>* cancel = nullptr);

  void ping();
  void pong(uint64_t nonce);

  uint32_t peer_version() const { return peer_version_; }
  uint64_t peer_services() const { return peer_services_; }
  bool peer_supports_bloom() const { return (peer_services_ & params::kNodeBloom) != 0; }
  int32_t peer_start_height() const { return peer_start_height_; }
  const std::string& peer_user_agent() const { return peer_user_agent_; }

  // Best-effort DNS A/AAAA lookup; returns IPv4 host strings.
  static std::vector<std::string> resolve_host(const std::string& host);
  static void global_init();
  static void global_cleanup();

 private:
  void send_raw(const Bytes& data);
  void ensure_recv(size_t need, int timeout_ms);
  bool wait_readable(int timeout_ms);

#ifdef _WIN32
  using Socket = uintptr_t;
  static constexpr Socket kInvalid = static_cast<Socket>(~static_cast<Socket>(0));
#else
  using Socket = int;
  static constexpr Socket kInvalid = -1;
#endif

  Socket sock_ = kInvalid;
  bool sock_valid_ = false;
  Bytes recv_buf_;
  std::string remote_host_;
  uint32_t peer_version_ = 0;
  uint64_t peer_services_ = 0;
  int32_t peer_start_height_ = 0;
  std::string peer_user_agent_;
  uint64_t local_nonce_ = 0;
};

}  // namespace net
}  // namespace ltc

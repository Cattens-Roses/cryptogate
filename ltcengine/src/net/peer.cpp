#include "ltc/net/peer.hpp"

#include "ltc/crypto/random.hpp"
#include "ltc/params.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ltc {
namespace net {
namespace {

#ifdef _WIN32
inline int last_err() { return WSAGetLastError(); }
#else
inline int last_err() { return errno; }
#endif

int g_wsa_refcount = 0;
std::mutex g_wsa_mu;

}  // namespace

void Peer::global_init() {
#ifdef _WIN32
  std::lock_guard<std::mutex> lock(g_wsa_mu);
  if (g_wsa_refcount++ == 0) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
      g_wsa_refcount = 0;
      throw std::runtime_error("WSAStartup failed");
    }
  }
#endif
}

void Peer::global_cleanup() {
#ifdef _WIN32
  std::lock_guard<std::mutex> lock(g_wsa_mu);
  if (g_wsa_refcount > 0 && --g_wsa_refcount == 0) WSACleanup();
#endif
}

Peer::Peer() { global_init(); }

Peer::~Peer() {
  disconnect();
  global_cleanup();
}

void Peer::disconnect() {
  if (sock_valid_) {
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(sock_));
#else
    ::close(sock_);
#endif
    sock_ = kInvalid;
    sock_valid_ = false;
  }
  recv_buf_.clear();
}

std::vector<std::string> Peer::resolve_host(const std::string& host) {
  global_init();
  std::vector<std::string> out;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
    global_cleanup();
    return out;
  }
  for (addrinfo* p = res; p; p = p->ai_next) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (p->ai_family == AF_INET) {
      auto* a = reinterpret_cast<sockaddr_in*>(p->ai_addr);
      if (inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf))) out.emplace_back(buf);
    } else if (p->ai_family == AF_INET6) {
      auto* a = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
      if (inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf))) out.emplace_back(buf);
    }
  }
  freeaddrinfo(res);
  global_cleanup();
  return out;
}

void Peer::connect(const std::string& host, uint16_t port, int timeout_ms, std::atomic<bool>* cancel) {
  disconnect();
  global_init();
  remote_host_ = host;
  if (timeout_ms < 200) timeout_ms = 200;
  if (timeout_ms > 10000) timeout_ms = 10000;
  if (cancel && cancel->load()) throw std::runtime_error("connect cancelled");

  // Prefer IPv4; Litecoin DNS seeds primarily advertise v4 peers.
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* res = nullptr;
  std::string port_str = std::to_string(port);
  int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
  if (rc != 0) {
    hints.ai_family = AF_UNSPEC;
    rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
  }
  if (rc != 0) throw std::runtime_error("DNS resolve failed for " + host);

  std::string last_err_msg;
  for (addrinfo* p = res; p; p = p->ai_next) {
    if (cancel && cancel->load()) {
      freeaddrinfo(res);
      throw std::runtime_error("connect cancelled");
    }
#ifdef _WIN32
    SOCKET s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (s == INVALID_SOCKET) continue;
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);
    int cr = ::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen));
    if (cr != 0) {
      int err = WSAGetLastError();
      if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        last_err_msg = "connect errno " + std::to_string(err);
        closesocket(s);
        continue;
      }
      int left = timeout_ms;
      bool ok = false;
      while (left > 0) {
        if (cancel && cancel->load()) {
          closesocket(s);
          freeaddrinfo(res);
          throw std::runtime_error("connect cancelled");
        }
        int slice = left > 100 ? 100 : left;
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = slice * 1000;
        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel > 0) {
          ok = true;
          break;
        }
        if (sel < 0) break;
        left -= slice;
      }
      if (!ok) {
        last_err_msg = "connect timeout";
        closesocket(s);
        continue;
      }
      int so_err = 0;
      int so_len = sizeof(so_err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
      if (so_err != 0) {
        last_err_msg = "connect errno " + std::to_string(so_err);
        closesocket(s);
        continue;
      }
    }
    nonblock = 0;
    ioctlsocket(s, FIONBIO, &nonblock);
    sock_ = static_cast<Socket>(s);
    sock_valid_ = true;
    break;
#else
    int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (s < 0) continue;
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    int cr = ::connect(s, p->ai_addr, p->ai_addrlen);
    if (cr != 0 && errno != EINPROGRESS) {
      last_err_msg = "connect errno " + std::to_string(errno);
      ::close(s);
      continue;
    }
    if (cr != 0) {
      int left = timeout_ms;
      bool ok = false;
      while (left > 0) {
        if (cancel && cancel->load()) {
          ::close(s);
          freeaddrinfo(res);
          throw std::runtime_error("connect cancelled");
        }
        int slice = left > 100 ? 100 : left;
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = slice * 1000;
        int sel = select(s + 1, nullptr, &wfds, nullptr, &tv);
        if (sel > 0) {
          ok = true;
          break;
        }
        if (sel < 0) break;
        left -= slice;
      }
      if (!ok) {
        last_err_msg = "connect timeout";
        ::close(s);
        continue;
      }
      int so_err = 0;
      socklen_t so_len = sizeof(so_err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
      if (so_err != 0) {
        last_err_msg = "connect errno " + std::to_string(so_err);
        ::close(s);
        continue;
      }
    }
    fcntl(s, F_SETFL, flags);
    sock_ = s;
    sock_valid_ = true;
    break;
#endif
  }
  freeaddrinfo(res);
  if (!sock_valid_) throw std::runtime_error("connect failed to " + host + ": " + last_err_msg);

  // Disable Nagle for snappier small messages; enlarge buffers; enable keepalive.
  int one = 1;
  int rcv = 1 << 20;  // 1 MiB
  int snd = 1 << 20;
#ifdef _WIN32
  setsockopt(static_cast<SOCKET>(sock_), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one),
             sizeof(one));
  setsockopt(static_cast<SOCKET>(sock_), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one),
             sizeof(one));
  setsockopt(static_cast<SOCKET>(sock_), SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcv),
             sizeof(rcv));
  setsockopt(static_cast<SOCKET>(sock_), SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&snd),
             sizeof(snd));
#else
  setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  setsockopt(sock_, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
  setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
#endif
}

void Peer::send_raw(const Bytes& data) {
  if (!sock_valid_) throw std::runtime_error("peer not connected");
  size_t sent = 0;
  while (sent < data.size()) {
#ifdef _WIN32
    int n = ::send(static_cast<SOCKET>(sock_), reinterpret_cast<const char*>(data.data() + sent),
                   static_cast<int>(data.size() - sent), 0);
#else
    ssize_t n = ::send(sock_, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
#endif
    if (n <= 0) throw std::runtime_error("send failed");
    sent += static_cast<size_t>(n);
  }
}

void Peer::send_message(const std::string& command, const Bytes& payload) {
  send_raw(encode_message(command, payload, params::kMagicMainnet));
}

bool Peer::wait_readable(int timeout_ms) {
  if (!sock_valid_) return false;
  fd_set rfds;
  FD_ZERO(&rfds);
#ifdef _WIN32
  FD_SET(static_cast<SOCKET>(sock_), &rfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int n = select(0, &rfds, nullptr, nullptr, timeout_ms < 0 ? nullptr : &tv);
#else
  FD_SET(sock_, &rfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int n = select(sock_ + 1, &rfds, nullptr, nullptr, timeout_ms < 0 ? nullptr : &tv);
#endif
  return n > 0;
}

void Peer::ensure_recv(size_t need, int timeout_ms) {
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (recv_buf_.size() < need) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) throw std::runtime_error("receive timeout");
    int remain =
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    if (!wait_readable(remain)) throw std::runtime_error("receive timeout");
    uint8_t tmp[65536];
#ifdef _WIN32
    int n = ::recv(static_cast<SOCKET>(sock_), reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
#else
    ssize_t n = ::recv(sock_, tmp, sizeof(tmp), 0);
#endif
    if (n == 0) throw std::runtime_error("peer closed connection");
    if (n < 0) throw std::runtime_error("recv failed");
    recv_buf_.insert(recv_buf_.end(), tmp, tmp + n);
  }
}

NetMessage Peer::receive_message(int timeout_ms) {
  if (!sock_valid_) throw std::runtime_error("peer not connected");
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  for (;;) {
    // Try decode from buffer first.
    if (recv_buf_.size() >= kHeaderSize) {
      try {
        NetMessage msg;
        size_t consumed =
            try_decode_message(recv_buf_.data(), recv_buf_.size(), msg, params::kMagicMainnet);
        if (consumed > 0) {
          recv_buf_.erase(recv_buf_.begin(),
                          recv_buf_.begin() + static_cast<std::ptrdiff_t>(consumed));
          return msg;
        }
      } catch (...) {
        // Bad framing — drop one byte and continue (or rethrow if clearly corrupt magic).
        if (recv_buf_.size() >= 4 && read_u32le(recv_buf_.data()) != params::kMagicMainnet) {
          recv_buf_.erase(recv_buf_.begin());
          continue;
        }
        throw;
      }
    }
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) throw std::runtime_error("receive timeout");
    int remain =
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    size_t before = recv_buf_.size();
    ensure_recv(before + 1, remain);
  }
}

void Peer::handshake(int32_t start_height, const std::string& user_agent, std::atomic<bool>* cancel) {
  if (cancel && cancel->load()) throw std::runtime_error("handshake cancelled");
  local_nonce_ = (uint64_t(random_u32()) << 32) | random_u32();
  auto now = std::chrono::system_clock::now().time_since_epoch();
  int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now).count();
  Bytes ver = encode_version(params::kProtocolVersion, params::kServices, ts, local_nonce_,
                             user_agent, start_height, true);
  send_message("version", ver);

  bool got_version = false;
  bool got_verack = false;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!(got_version && got_verack)) {
    if (cancel && cancel->load()) throw std::runtime_error("handshake cancelled");
    if (std::chrono::steady_clock::now() >= deadline) break;
    NetMessage msg = receive_message(1000);
    if (msg.command == "version") {
      uint32_t ver_n = 0;
      uint64_t services = 0;
      int64_t timestamp = 0;
      uint64_t nonce = 0;
      std::string ua;
      int32_t height = 0;
      bool relay = true;
      if (!decode_version(msg.payload, ver_n, services, timestamp, nonce, ua, height, relay))
        throw std::runtime_error("bad version payload");
      peer_version_ = ver_n;
      peer_services_ = services;
      peer_start_height_ = height;
      peer_user_agent_ = ua;
      send_message("verack");
      got_version = true;
    } else if (msg.command == "verack") {
      got_verack = true;
    } else if (msg.command == "ping") {
      pong(decode_nonce64(msg.payload));
    }
    // Ignore sendheaders/sendcmpct/feefilter/addr — do not burn a fixed message budget.
  }
  if (!got_version || !got_verack) throw std::runtime_error("handshake incomplete");
}

void Peer::ping() {
  uint64_t nonce = (uint64_t(random_u32()) << 32) | random_u32();
  send_message("ping", encode_ping(nonce));
}

void Peer::pong(uint64_t nonce) { send_message("pong", encode_pong(nonce)); }

}  // namespace net
}  // namespace ltc

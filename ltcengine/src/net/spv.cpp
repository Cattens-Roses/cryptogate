#include "ltc/net/spv.hpp"

#include "ltc/crypto/hash.hpp"
#include "ltc/crypto/random.hpp"
#include "ltc/params.hpp"
#include "ltc/util/error_log.hpp"
#include "ltc/util/fs.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ltc {
namespace net {
namespace {

std::string hash_hex(const Hash256& h) { return to_hex(h.data(), h.size()); }

Hash256 genesis_hash() {
  Bytes h = from_hex(params::kGenesisHashHex);
  if (h.size() != 32) throw std::runtime_error("bad genesis hash");
  // Display hex is reversed relative to internal byte order used on wire.
  std::reverse(h.begin(), h.end());
  Hash256 out{};
  std::memcpy(out.data(), h.data(), 32);
  return out;
}

Hash256 hash_nodes(const Hash256& a, const Hash256& b) {
  Bytes buf;
  buf.reserve(64);
  append_bytes(buf, a.data(), 32);
  append_bytes(buf, b.data(), 32);
  return double_sha256(buf);
}

struct PartialMerkle {
  uint32_t total_txs = 0;
  std::vector<Hash256> hashes;
  std::vector<bool> bits;

  // Traverse and collect matched txids; verify merkle root.
  bool extract(Hash256& merkle_root, std::vector<Hash256>& matches) const {
    size_t bit_pos = 0;
    size_t hash_pos = 0;
    auto height_of = [&](uint32_t /*unused*/) {
      uint32_t height = 0;
      while ((1u << height) < total_txs) ++height;
      return height;
    };
    std::function<Hash256(int, uint32_t)> traverse = [&](int height, uint32_t pos) -> Hash256 {
      if (bit_pos >= bits.size()) throw std::runtime_error("merkle bits overrun");
      bool parent_of_match = bits[bit_pos++];
      if (height == 0 || !parent_of_match) {
        if (hash_pos >= hashes.size()) throw std::runtime_error("merkle hashes overrun");
        Hash256 h = hashes[hash_pos++];
        if (height == 0 && parent_of_match) matches.push_back(h);
        return h;
      }
      Hash256 left = traverse(height - 1, pos * 2);
      Hash256 right;
      if (pos * 2 + 1 < ((total_txs + (1u << (height - 1)) - 1) >> (height - 1))) {
        right = traverse(height - 1, pos * 2 + 1);
      } else {
        right = left;
      }
      return hash_nodes(left, right);
    };
    int height = static_cast<int>(height_of(0));
    merkle_root = traverse(height, 0);
    return bit_pos <= bits.size() && hash_pos == hashes.size();
  }
};

PartialMerkle decode_partial_merkle(const uint8_t*& p, const uint8_t* end) {
  PartialMerkle pm;
  if (p + 4 > end) throw std::runtime_error("merkleblock underflow");
  pm.total_txs = read_u32le(p);
  p += 4;
  uint64_t n_hashes = read_varint(p, end);
  pm.hashes.resize(static_cast<size_t>(n_hashes));
  for (uint64_t i = 0; i < n_hashes; ++i) {
    if (p + 32 > end) throw std::runtime_error("merkle hash underflow");
    std::memcpy(pm.hashes[static_cast<size_t>(i)].data(), p, 32);
    p += 32;
  }
  Bytes flag_bytes = read_varbytes(p, end);
  pm.bits.reserve(flag_bytes.size() * 8);
  for (uint8_t b : flag_bytes) {
    for (int i = 0; i < 8; ++i) pm.bits.push_back(((b >> i) & 1) != 0);
  }
  return pm;
}

}  // namespace

MerkleBlockMatch parse_merkleblock(const Bytes& payload) {
  const uint8_t* p = payload.data();
  const uint8_t* end = p + payload.size();
  MerkleBlockMatch out;
  out.header = BlockHeader::deserialize(p, end);
  p += 80;
  PartialMerkle pm = decode_partial_merkle(p, end);
  Hash256 root{};
  if (!pm.extract(root, out.matched_txids)) throw std::runtime_error("partial merkle extract failed");
  if (root != out.header.merkle_root) throw std::runtime_error("merkle root mismatch");
  return out;
}

SpvNode::SpvNode(std::string data_dir) : data_dir_(std::move(data_dir)) {
  fs::ensure_dir(data_dir_);
  set_error_log_dir(data_dir_);
  Peer::global_init();
  load_headers();
  if (tip_height_ == 0 && tip_hash_ == Hash256{}) {
    tip_hash_ = genesis_hash();
    tip_height_ = 0;
    disk_height_ = 0;
    push_recent(0, tip_hash_);
  }
}

SpvNode::~SpvNode() {
  try {
    flush_headers();
  } catch (const std::exception& e) {
    log_error(e.what(), "spv/flush");
  } catch (...) {
    log_error("flush_headers failed", "spv/flush");
  }
  peers_.clear();
  Peer::global_cleanup();
}

std::string SpvNode::headers_path() const { return fs::join(data_dir_, "headers.dat"); }
std::string SpvNode::tip_path() const { return fs::join(data_dir_, "headers.tip"); }

void SpvNode::write_tip_file() const {
  std::ostringstream oss;
  oss << "TIP1\nheight=" << tip_height_ << "\nhash=" << to_hex(tip_hash_.data(), tip_hash_.size())
      << "\n";
  fs::write_file(tip_path(), oss.str());
}

bool SpvNode::read_tip_file(uint32_t& height, Hash256& tip) const {
  if (!fs::file_exists(tip_path())) return false;
  try {
    std::string text = fs::read_text(tip_path());
    std::istringstream iss(text);
    std::string line;
    if (!std::getline(iss, line) || line != "TIP1") return false;
    height = 0;
    tip = Hash256{};
    bool got_h = false, got_hash = false;
    while (std::getline(iss, line)) {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      std::string key = line.substr(0, eq);
      std::string val = line.substr(eq + 1);
      if (key == "height") {
        height = static_cast<uint32_t>(std::stoul(val));
        got_h = true;
      } else if (key == "hash") {
        Bytes raw = from_hex(val);
        if (raw.size() != 32) return false;
        std::memcpy(tip.data(), raw.data(), 32);
        got_hash = true;
      }
    }
    return got_h && got_hash;
  } catch (...) {
    return false;
  }
}

bool SpvNode::read_disk_header(uint32_t height, BlockHeader& out) const {
  if (height == 0 || height > disk_height_) return false;
  std::ifstream in(headers_path(), std::ios::binary);
  if (!in) return false;
  std::uint64_t off = static_cast<std::uint64_t>(height - 1) * 80ull;
  in.seekg(static_cast<std::streamoff>(off));
  uint8_t buf[80];
  in.read(reinterpret_cast<char*>(buf), 80);
  if (!in) return false;
  out = BlockHeader::deserialize(buf, buf + 80);
  return true;
}

Hash256 SpvNode::hash_at_disk(uint32_t height) const {
  if (height == 0) return genesis_hash();
  BlockHeader h;
  if (!read_disk_header(height, h)) throw std::runtime_error("header missing on disk");
  return h.hash();
}

void SpvNode::push_recent(uint32_t height, const Hash256& hash) {
  if (recent_hashes_.empty()) {
    recent_base_ = height;
    recent_hashes_.push_back(hash);
    return;
  }
  uint32_t expect = recent_base_ + static_cast<uint32_t>(recent_hashes_.size());
  if (height == expect) {
    recent_hashes_.push_back(hash);
  } else if (height + 1 == expect && !recent_hashes_.empty() &&
             recent_hashes_.back() == hash) {
    return;  // duplicate tip
  } else {
    // Reset cache around this tip.
    recent_base_ = height;
    recent_hashes_.clear();
    recent_hashes_.push_back(hash);
  }
  while (recent_hashes_.size() > kRecentWindow) {
    recent_hashes_.erase(recent_hashes_.begin());
    ++recent_base_;
  }
}

void SpvNode::preload_recent_cache() {
  recent_hashes_.clear();
  // Keep only a small warm window — full 8k preload was ~300ms on every start.
  constexpr uint32_t kWarm = 512;
  if (tip_height_ == 0) {
    push_recent(0, tip_hash_);
    return;
  }
  uint32_t start = tip_height_ + 1 > kWarm ? tip_height_ + 1 - kWarm : 0;
  recent_base_ = start;
  recent_hashes_.reserve(tip_height_ - start + 1);
  for (uint32_t h = start; h <= tip_height_; ++h) {
    if (h == tip_height_)
      recent_hashes_.push_back(tip_hash_);
    else if (h == 0)
      recent_hashes_.push_back(genesis_hash());
    else if (h <= disk_height_)
      recent_hashes_.push_back(hash_at_disk(h));
    else {
      size_t pi = static_cast<size_t>(h - disk_height_ - 1);
      if (pi < pending_.size()) recent_hashes_.push_back(pending_[pi].hash);
    }
  }
}

Hash256 SpvNode::hash_at(uint32_t height) const {
  if (height > tip_height_) throw std::runtime_error("hash_at past tip");
  if (height == tip_height_) return tip_hash_;
  if (height == 0) return genesis_hash();
  if (!recent_hashes_.empty() && height >= recent_base_ &&
      height < recent_base_ + recent_hashes_.size()) {
    return recent_hashes_[height - recent_base_];
  }
  if (height > disk_height_) {
    size_t pi = static_cast<size_t>(height - disk_height_ - 1);
    if (pi >= pending_.size()) throw std::runtime_error("hash_at pending miss");
    return pending_[pi].hash;
  }
  return hash_at_disk(height);
}

bool SpvNode::find_height_for_hash(const Hash256& bh, uint32_t& height_out) const {
  if (bh == tip_hash_) {
    height_out = tip_height_;
    return true;
  }
  if (!recent_hashes_.empty()) {
    for (size_t i = recent_hashes_.size(); i-- > 0;) {
      if (recent_hashes_[i] == bh) {
        height_out = recent_base_ + static_cast<uint32_t>(i);
        return true;
      }
    }
  }
  for (size_t i = pending_.size(); i-- > 0;) {
    if (pending_[i].hash == bh) {
      height_out = disk_height_ + 1 + static_cast<uint32_t>(i);
      return true;
    }
  }
  return false;
}

void SpvNode::load_headers() {
  pending_.clear();
  recent_hashes_.clear();
  tip_height_ = 0;
  tip_hash_ = Hash256{};
  disk_height_ = 0;
  headers_since_flush_ = 0;
  last_progress_height_ = 0;

  std::string path = headers_path();
  if (!fs::file_exists(path)) {
    tip_hash_ = genesis_hash();
    tip_height_ = 0;
    push_recent(0, tip_hash_);
    return;
  }

  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in) return;
  std::streamoff sz = in.tellg();
  if (sz < 0) return;
  size_t file_bytes = static_cast<size_t>(sz);
  size_t usable = file_bytes - (file_bytes % 80);
  uint32_t file_height = static_cast<uint32_t>(usable / 80);  // heights 1..file_height

  // Fast path: trust tip file if it matches file size + last header hash.
  uint32_t tip_h = 0;
  Hash256 tip{};
  if (file_height > 0 && read_tip_file(tip_h, tip) && tip_h == file_height) {
    BlockHeader last;
    disk_height_ = file_height;
    if (read_disk_header(file_height, last) && last.hash() == tip) {
      // Spot-check genesis link for height 1.
      BlockHeader first;
      if (read_disk_header(1, first) && first.prev == genesis_hash()) {
        tip_height_ = tip_h;
        tip_hash_ = tip;
        last_progress_height_ = tip_height_;
        preload_recent_cache();
        return;
      }
    }
  }

  // Slow path (first run / corrupt tip): stream-verify without keeping all headers in RAM.
  in.clear();
  in.seekg(0);
  Hash256 expect_prev = genesis_hash();
  uint32_t height = 0;
  size_t good_bytes = 0;
  uint8_t buf[80];
  while (good_bytes + 80 <= usable && in.read(reinterpret_cast<char*>(buf), 80)) {
    BlockHeader h = BlockHeader::deserialize(buf, buf + 80);
    if (h.prev != expect_prev) break;
    expect_prev = h.hash();
    ++height;
    good_bytes += 80;
  }
  tip_height_ = height;
  tip_hash_ = expect_prev;
  disk_height_ = height;
  last_progress_height_ = tip_height_;
  if (good_bytes < file_bytes) {
    // Truncate trailing garbage.
    std::ifstream rin(path, std::ios::binary);
    Bytes keep(good_bytes);
    if (good_bytes > 0 && rin)
      rin.read(reinterpret_cast<char*>(keep.data()), static_cast<std::streamsize>(good_bytes));
    fs::write_file(path, keep);
  }
  write_tip_file();
  preload_recent_cache();
}

void SpvNode::flush_headers() {
  if (pending_.empty()) return;
  Bytes out;
  out.reserve(pending_.size() * 80);
  for (const auto& p : pending_) {
    Bytes raw = p.header.serialize();
    append_bytes(out, raw);
  }
  fs::append_file(headers_path(), out);
  disk_height_ += static_cast<uint32_t>(pending_.size());
  pending_.clear();
  headers_since_flush_ = 0;
  write_tip_file();
}

void SpvNode::save_headers() const {
  // Full rewrite not needed with append-only + tip file; flush pending via const_cast path.
  const_cast<SpvNode*>(this)->flush_headers();
}

std::vector<Hash256> SpvNode::build_locator() const {
  std::vector<Hash256> locator;
  Hash256 gen = genesis_hash();
  if (tip_height_ == 0) {
    locator.push_back(tip_hash_ == Hash256{} ? gen : tip_hash_);
    return locator;
  }
  int64_t index = static_cast<int64_t>(tip_height_);
  int step = 1;
  while (index >= 0) {
    locator.push_back(hash_at(static_cast<uint32_t>(index)));
    if (locator.size() >= 10) step *= 2;
    index -= step;
  }
  if (locator.empty() || locator.back() != gen) locator.push_back(gen);
  return locator;
}

bool SpvNode::connect_peers(size_t min_peers, size_t max_peers, bool prefer_bloom) {
  peers_.clear();
  active_idx_ = 0;
  if (min_peers == 0) min_peers = 1;
  if (max_peers < min_peers) max_peers = min_peers;

  constexpr int kBudgetMs = 2000;
  constexpr int kDialTimeoutMs = 700;
  constexpr size_t kParallel = 8;
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + std::chrono::milliseconds(kBudgetMs);
  const std::string cache_path = fs::join(data_dir_, "peers.dat");

  auto load_cache = [&]() -> std::vector<std::string> {
    std::vector<std::string> out;
    if (!fs::file_exists(cache_path)) return out;
    try {
      std::istringstream iss(fs::read_text(cache_path));
      std::string line;
      while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (!line.empty()) out.push_back(line);
      }
    } catch (...) {
    }
    return out;
  };

  auto save_cache = [&](const std::vector<std::string>& ips) {
    if (ips.empty()) return;
    std::ostringstream oss;
    size_t n = 0;
    for (const auto& ip : ips) {
      oss << ip << "\n";
      if (++n >= 32) break;
    }
    try {
      fs::write_file(cache_path, oss.str());
    } catch (...) {
    }
  };

  // Shared with detached DNS threads so they never touch stack locals after return.
  struct HostFanout {
    std::mutex mu;
    std::deque<std::string> queue;
    std::unordered_set<std::string> seen;
    std::atomic<bool> accept{true};
    std::atomic<bool> stop{false};
    std::atomic<int> inflight{0};
    std::string cache_path;
    void enqueue(const std::string& h) {
      if (h.empty() || !accept.load()) return;
      std::lock_guard<std::mutex> lock(mu);
      if (!seen.insert(h).second) return;
      queue.push_back(h);
    }
    void merge_cache(const std::vector<std::string>& ips) {
      if (ips.empty() || cache_path.empty()) return;
      try {
        std::unordered_set<std::string> all;
        if (fs::file_exists(cache_path)) {
          std::istringstream iss(fs::read_text(cache_path));
          std::string line;
          while (std::getline(iss, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (!line.empty()) all.insert(line);
          }
        }
        for (const auto& ip : ips) all.insert(ip);
        std::ostringstream oss;
        size_t n = 0;
        for (const auto& ip : all) {
          oss << ip << "\n";
          if (++n >= 32) break;
        }
        fs::write_file(cache_path, oss.str());
      } catch (...) {
      }
    }
  };
  auto hosts = std::make_shared<HostFanout>();
  hosts->cache_path = cache_path;
  for (const auto& h : load_cache()) hosts->enqueue(h);
  const size_t cached_n = hosts->seen.size();

  std::vector<std::thread> dns_pool;

  auto start_dns = [&]() {
    if (hosts->inflight.load() > 0 || !dns_pool.empty()) return;
    int seeds = 0;
    for (const char** s = params::kDnsSeeds; *s && seeds < 5; ++s, ++seeds) {
      const char* seed = *s;
      hosts->inflight.fetch_add(1);
      dns_pool.emplace_back([hosts, seed]() {
        try {
          auto addrs = Peer::resolve_host(seed);
          if (hosts->accept.load() && !hosts->stop.load()) {
            for (const auto& a : addrs) hosts->enqueue(a);
          } else {
            hosts->merge_cache(addrs);
          }
        } catch (...) {
        }
        hosts->inflight.fetch_sub(1);
      });
    }
  };

  if (cached_n == 0) start_dns();

  struct Result {
    std::string host;
    std::unique_ptr<Peer> peer;
    std::string error;
  };
  std::mutex mu;
  std::vector<Result> results;
  const int32_t tip = static_cast<int32_t>(tip_height_);

  auto worker = [&]() {
    for (;;) {
      if (hosts->stop.load()) return;
      if (std::chrono::steady_clock::now() >= deadline) {
        hosts->stop = true;
        return;
      }
      std::string host;
      {
        std::lock_guard<std::mutex> lock(hosts->mu);
        if (!hosts->queue.empty()) {
          host = hosts->queue.front();
          hosts->queue.pop_front();
        }
      }
      if (host.empty()) {
        // Stay alive: coordinator may still start DNS after cached dials fail.
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        continue;
      }
      try {
        auto peer = std::make_unique<Peer>();
        peer->connect(host, params::kDefaultPort, kDialTimeoutMs, &hosts->stop);
        if (hosts->stop.load()) return;
        peer->handshake(tip, "/ltcengine:1.0.0/", &hosts->stop);
        Result r;
        r.host = host;
        r.peer = std::move(peer);
        std::lock_guard<std::mutex> lock(mu);
        results.push_back(std::move(r));
      } catch (const std::exception& e) {
        if (hosts->stop.load()) return;
        std::lock_guard<std::mutex> lock(mu);
        Result r;
        r.host = host;
        r.error = e.what();
        results.push_back(std::move(r));
      } catch (...) {
        if (hosts->stop.load()) return;
        std::lock_guard<std::mutex> lock(mu);
        Result r;
        r.host = host;
        r.error = "dial failed";
        results.push_back(std::move(r));
      }
    }
  };

  std::vector<std::thread> pool;
  pool.reserve(kParallel);
  for (size_t w = 0; w < kParallel; ++w) pool.emplace_back(worker);

  auto count_ready = [&](size_t& bloom_n, size_t& any_n) {
    bloom_n = 0;
    any_n = 0;
    std::lock_guard<std::mutex> lock(mu);
    for (const auto& r : results) {
      if (!r.peer) continue;
      if (r.peer->peer_supports_bloom())
        ++bloom_n;
      else
        ++any_n;
    }
  };

  for (;;) {
    size_t bloom_n = 0, any_n = 0;
    count_ready(bloom_n, any_n);
    size_t ready = bloom_n + any_n;
    bool bloom_ok = !prefer_bloom || bloom_n > 0;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
    // Prefer NODE_BLOOM peers; only soft-accept non-bloom near the deadline.
    bool soft = !prefer_bloom || elapsed >= (kBudgetMs - 200);
    if (ready >= min_peers && (bloom_ok || soft)) hosts->stop = true;
    if (ready >= max_peers && bloom_ok) hosts->stop = true;
    if (!prefer_bloom && ready >= max_peers) hosts->stop = true;
    if (hosts->stop.load()) break;
    if (now >= deadline) {
      hosts->stop = true;
      break;
    }
    if (cached_n > 0 && elapsed >= 350 && dns_pool.empty() && ready < min_peers) start_dns();

    bool idle = false;
    {
      std::lock_guard<std::mutex> lock(hosts->mu);
      idle = hosts->queue.empty() && hosts->inflight.load() == 0;
    }
    if (idle) {
      size_t before, after;
      {
        std::lock_guard<std::mutex> lock(mu);
        before = results.size();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      {
        std::lock_guard<std::mutex> lock(mu);
        after = results.size();
      }
      if (before == after) {
        if (dns_pool.empty() && ready < min_peers && now < deadline) {
          start_dns();
          continue;
        }
        hosts->stop = true;
        break;
      }
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  hosts->stop = true;
  hosts->accept = false;
  for (auto& t : pool) {
    if (t.joinable()) t.join();
  }
  for (auto& t : dns_pool) {
    if (t.joinable()) t.detach();
  }

  std::vector<std::unique_ptr<Peer>> got_bloom;
  std::vector<std::unique_ptr<Peer>> got_any;
  std::vector<std::string> good_ips;
  std::string last_error;
  for (auto& r : results) {
    if (!r.peer) {
      if (!r.error.empty()) last_error = r.host + ": " + r.error;
      continue;
    }
    good_ips.push_back(r.host);
    if (r.peer->peer_supports_bloom())
      got_bloom.push_back(std::move(r.peer));
    else
      got_any.push_back(std::move(r.peer));
  }

  for (auto& p : got_bloom) {
    if (peers_.size() >= max_peers) break;
    peers_.push_back(std::move(p));
  }
  for (auto& p : got_any) {
    if (peers_.size() >= max_peers) break;
    peers_.push_back(std::move(p));
  }

  select_active(prefer_bloom);
  if (!good_ips.empty()) save_cache(good_ips);

  if (peers_.size() < min_peers) {
    std::string msg = "no peers available";
    if (!last_error.empty()) msg += " (last: " + last_error + ")";
    log_error(msg, "connect_peers");
    throw std::runtime_error(msg);
  }
  return true;
}

void SpvNode::select_active(bool prefer_bloom) {
  if (peers_.empty()) {
    active_idx_ = 0;
    return;
  }
  if (prefer_bloom) {
    for (size_t i = 0; i < peers_.size(); ++i) {
      if (peers_[i]->peer_supports_bloom()) {
        active_idx_ = i;
        return;
      }
    }
  }
  if (active_idx_ >= peers_.size()) active_idx_ = 0;
}

bool SpvNode::is_hard_peer_error(const std::string& what) {
  return what.find("peer closed") != std::string::npos ||
         what.find("recv failed") != std::string::npos ||
         what.find("send failed") != std::string::npos ||
         what.find("connect failed") != std::string::npos ||
         what.find("connect timeout") != std::string::npos;
}

Peer* SpvNode::active_peer() {
  if (peers_.empty()) return nullptr;
  if (active_idx_ >= peers_.size()) active_idx_ = 0;
  return peers_[active_idx_].get();
}

Peer* SpvNode::primary_peer() { return active_peer(); }

bool SpvNode::has_peer() const { return !peers_.empty(); }

bool SpvNode::drop_peer(Peer* peer) {
  if (!peer || peers_.empty()) return false;
  for (size_t i = 0; i < peers_.size(); ++i) {
    if (peers_[i].get() != peer) continue;
    std::string ua = peers_[i]->peer_user_agent();
    peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
    if (peers_.empty()) {
      active_idx_ = 0;
    } else if (i < active_idx_) {
      --active_idx_;
    } else if (active_idx_ >= peers_.size()) {
      active_idx_ = 0;
    }
    log_error("dropped " + ua + "; pool=" + std::to_string(peers_.size()), "rotate_peer");
    return true;
  }
  return false;
}

bool SpvNode::rotate_peer(bool prefer_bloom) {
  Peer* cur = active_peer();
  if (cur) drop_peer(cur);

  if (peers_.empty()) {
    log_error("pool empty; rediscovering peers", "rotate_peer");
    if (!connect_peers(1, 4, prefer_bloom || bloom_set_)) return false;
  } else {
    select_active(prefer_bloom || bloom_set_);
  }

  Peer* next = active_peer();
  if (!next) return false;
  log_error("active -> " + next->peer_user_agent() +
                (next->peer_supports_bloom() ? " (bloom)" : " (no-bloom)"),
            "rotate_peer");
  if (bloom_set_) {
    try {
      send_filterload();
    } catch (const std::exception& e) {
      log_error(e.what(), "rotate_peer/filterload");
    }
  }
  return true;
}

bool SpvNode::ensure_peers(size_t min_peers, size_t max_peers, bool prefer_bloom) {
  if (peers_.size() >= min_peers) {
    select_active(prefer_bloom);
    return true;
  }
  if (!peers_.empty()) {
    // Still have someone — usable even if below preferred min.
    select_active(prefer_bloom);
    return true;
  }
  return connect_peers(min_peers, max_peers, prefer_bloom);
}

void SpvNode::ensure_peer() {
  if (!ensure_peers(1, 4, bloom_set_)) throw std::runtime_error("no peers available");
}

void SpvNode::set_bloom(const BloomFilter& filter) {
  bloom_ = filter;
  bloom_set_ = true;
}

void SpvNode::send_filterload() {
  ensure_peer();
  if (!bloom_set_) throw std::runtime_error("bloom filter not set");
  Peer* peer = active_peer();
  if (!peer) throw std::runtime_error("no peers available");
  if (!peer->peer_supports_bloom()) {
    // Sending filterload to non-bloom peers causes an immediate disconnect.
    return;
  }
  peer->send_message("filterload", bloom_.serialize_filterload());
}

void SpvNode::handle_ping(Peer& peer, const NetMessage& msg) {
  if (msg.command == "ping" && msg.payload.size() >= 8) peer.pong(decode_nonce64(msg.payload));
}

void SpvNode::request_headers(Peer& peer) {
  auto locator = build_locator();
  peer.send_message("getheaders",
                    encode_getheaders(params::kProtocolVersion, locator, Hash256{}));
}

int SpvNode::process_headers_msg(const Bytes& payload, ProgressFn& on_progress) {
  auto batch = decode_headers(payload);
  if (batch.empty()) return 0;  // caught up
  size_t added = 0;
  for (const auto& h : batch) {
    if (h.prev != tip_hash_) {
      if (!(tip_height_ == 0 && h.prev == genesis_hash())) {
        continue;
      }
    }
    Hash256 hh = h.hash();
    pending_.push_back(PendingHeader{h, hh});
    tip_hash_ = hh;
    tip_height_ = disk_height_ + static_cast<uint32_t>(pending_.size());
    push_recent(tip_height_, hh);
    ++added;
  }
  if (added == 0) {
    // Headers did not attach to our tip — retry/rotate, do not treat as synced.
    return -1;
  }
  headers_since_flush_ += added;
  // Flush often enough to keep pending_ small (RAM), and persist tip.
  if (headers_since_flush_ >= 2000 || pending_.size() >= 2000) flush_headers();

  if (on_progress &&
      (tip_height_ >= last_progress_height_ + 2000 || tip_height_ < last_progress_height_)) {
    last_progress_height_ = tip_height_;
    on_progress(tip_height_, tip_hash_);
  }
  return (batch.size() >= 2000 && added >= 2000) ? 1 : 0;
}

void SpvNode::sync_headers(ProgressFn on_progress) {
  ensure_peer();
  for (int round = 0; round < 100000; ++round) {
    int r = sync_headers_round(on_progress, nullptr);
    if (r == 0) break;
    if (r < 0) continue;
  }
  flush_headers();
  if (on_progress) on_progress(tip_height_, tip_hash_);
}

int SpvNode::sync_headers_round(ProgressFn on_progress, std::atomic<bool>* stop) {
  ensure_peer();
  Peer* peer = active_peer();
  if (!peer) throw std::runtime_error("no peers available");
  try {
    request_headers(*peer);
  } catch (const std::exception& e) {
    log_error(e.what(), "sync_headers");
    if (!rotate_peer(false)) throw;
    peer = active_peer();
    if (!peer) throw;
    request_headers(*peer);
  }
  bool more = false;
  bool got = false;
  // Keep the pipe hot: short polls, long overall wait, ignore non-header chatter.
  for (int wait = 0; wait < 120 && !got; ++wait) {
    if (stop && stop->load()) {
      flush_headers();
      return 0;
    }
    peer = active_peer();
    if (!peer) {
      if (!rotate_peer(false)) throw std::runtime_error("no peers available");
      peer = active_peer();
      request_headers(*peer);
      continue;
    }
    try {
      NetMessage msg = peer->receive_message(1000);
      handle_ping(*peer, msg);
      if (msg.command == "headers") {
        int pr = process_headers_msg(msg.payload, on_progress);
        if (pr < 0) {
          // Non-connecting batch — rotate and retry; do not mark synced.
          flush_headers();
          log_error("headers batch did not extend tip", "sync_headers");
          if (!rotate_peer(false)) return -1;
          peer = active_peer();
          if (peer) request_headers(*peer);
          continue;
        }
        more = pr > 0;
        got = true;
      } else if (msg.command == "ping" || msg.command == "pong" || msg.command == "sendheaders" ||
                 msg.command == "sendcmpct" || msg.command == "feefilter" || msg.command == "addr" ||
                 msg.command == "inv") {
        // drain / ignore during header sync for speed
        continue;
      }
    } catch (const std::runtime_error& e) {
      std::string what = e.what();
      if (is_hard_peer_error(what)) {
        flush_headers();
        log_error(what, "sync_headers");
        if (!rotate_peer(false)) throw;
        peer = active_peer();
        if (!peer) throw;
        try {
          request_headers(*peer);
        } catch (const std::exception& re) {
          log_error(re.what(), "sync_headers");
          if (!rotate_peer(false)) throw;
        }
        continue;
      }
      // timeout — ask again once in a while
      if (wait > 0 && wait % 15 == 0) {
        try {
          peer->ping();
          request_headers(*peer);
        } catch (const std::exception& pe) {
          flush_headers();
          log_error(pe.what(), "sync_headers/ping");
          if (!rotate_peer(false)) throw;
          peer = active_peer();
          if (!peer) throw;
          try {
            request_headers(*peer);
          } catch (...) {
            if (!rotate_peer(false)) throw;
          }
        }
      }
    }
  }
  if (!got) return -1;  // transient — retry
  return more ? 1 : 0;
}

void SpvNode::request_filtered_blocks(Peer& peer) {
  auto locator = build_locator();
  peer.send_message("getblocks", encode_getblocks(params::kProtocolVersion, locator, Hash256{}));
}

bool SpvNode::handle_filter_message(Peer& peer, const NetMessage& msg, TxHandler& on_tx,
                                    ProgressFn& on_progress) {
  if (msg.command == "inv") {
    auto items = decode_inv(msg.payload);
    std::vector<InvVector> want;
    const bool can_filter = peer.peer_supports_bloom() && bloom_set_;
    for (auto& it : items) {
      if (it.type == InvType::Tx || it.type == InvType::WitnessTx) {
        want.push_back(it);
      } else if (can_filter &&
                 (it.type == InvType::Block || it.type == InvType::WitnessBlock ||
                  it.type == InvType::FilteredBlock || it.type == InvType::FilteredWitnessBlock)) {
        InvVector v;
        v.type = InvType::FilteredBlock;
        v.hash = it.hash;
        want.push_back(v);
      }
    }
    if (!want.empty()) peer.send_message("getdata", encode_getdata(want));
    return false;
  }
  if (msg.command == "merkleblock") {
    MerkleBlockMatch mb = parse_merkleblock(msg.payload);
    Hash256 bh = mb.header.hash();
    uint32_t height = 0;
    bool have_height = find_height_for_hash(bh, height);
    if (mb.header.prev == tip_hash_) {
      pending_.push_back(PendingHeader{mb.header, bh});
      tip_hash_ = bh;
      tip_height_ = disk_height_ + static_cast<uint32_t>(pending_.size());
      height = tip_height_;
      have_height = true;
      push_recent(tip_height_, bh);
      ++headers_since_flush_;
      if (headers_since_flush_ >= 200 || pending_.size() >= 200) flush_headers();
      if (on_progress) on_progress(tip_height_, tip_hash_);
    }
    for (const auto& txid : mb.matched_txids) {
      std::string key = hash_hex(txid);
      pending_txids_.insert(key);
      if (have_height) {
        txid_height_[key] = height;
        txid_block_[key] = bh;
      }
    }
    return true;
  }
  if (msg.command == "tx") {
    Transaction tx = deserialize_tx(msg.payload);
    Hash256 id = tx.txid();
    std::string key = hash_hex(id);
    bool accept = pending_txids_.count(key) != 0;
    if (!accept && bloom_set_) {
      for (const auto& out : tx.vout) {
        if (bloom_.contains(out.script_pubkey)) {
          accept = true;
          break;
        }
      }
      if (!accept) {
        for (const auto& in : tx.vin) {
          Bytes op;
          append_bytes(op, in.prev.txid.data(), 32);
          append_u32le(op, in.prev.vout);
          if (bloom_.contains(op)) {
            accept = true;
            break;
          }
        }
      }
    }
    if (accept) {
      pending_txids_.erase(key);
      uint32_t height = 0;
      Hash256 block{};
      auto hit = txid_height_.find(key);
      if (hit != txid_height_.end()) height = hit->second;
      auto bhit = txid_block_.find(key);
      if (bhit != txid_block_.end()) block = bhit->second;
      if (on_tx) on_tx(tx, height, block);
    }
    return false;
  }
  if (msg.command == "headers") {
    ProgressFn nop;
    process_headers_msg(msg.payload, on_progress ? on_progress : nop);
  }
  return false;
}

uint32_t SpvNode::rescan_filtered(uint32_t from_height, TxHandler on_tx, ProgressFn on_progress,
                                  std::atomic<bool>* stop) {
  ensure_peer();
  if (!bloom_set_) throw std::runtime_error("bloom filter not set");
  Peer* peer = active_peer();
  if (!peer) throw std::runtime_error("no peers available");

  auto refresh_peer_mode = [&](bool& use_bloom) {
    peer = active_peer();
    if (!peer) throw std::runtime_error("no peers available");
    use_bloom = peer->peer_supports_bloom();
    if (use_bloom) {
      send_filterload();
    } else {
      log_error("peer lacks NODE_BLOOM; scanning recent full blocks locally", "rescan");
    }
  };

  bool use_bloom = false;
  refresh_peer_mode(use_bloom);

  if (tip_height_ == 0) return 0;
  uint32_t cursor = from_height;
  if (cursor >= tip_height_) return tip_height_;

  // Without BIP37, only scan a small tip window (full blocks are large).
  if (!use_bloom) {
    constexpr uint32_t kFullWindow = 128;
    if (tip_height_ > kFullWindow && cursor < tip_height_ - kFullWindow)
      cursor = tip_height_ - kFullWindow;
  }

  constexpr uint32_t kBatch = 16;
  uint32_t start = cursor + 1;
  if (start < 1) start = 1;

  for (uint32_t h = start; h <= tip_height_;) {
    if (stop && stop->load()) break;
    peer = active_peer();
    if (!peer) {
      if (!rotate_peer(true)) throw std::runtime_error("no peers available");
      refresh_peer_mode(use_bloom);
      continue;
    }

    uint32_t end = h + kBatch - 1;
    if (end > tip_height_) end = tip_height_;

    std::vector<InvVector> want;
    want.reserve(end - h + 1);
    std::unordered_map<std::string, uint32_t> expect;
    for (uint32_t i = h; i <= end; ++i) {
      InvVector v;
      v.type = use_bloom ? InvType::FilteredBlock : InvType::WitnessBlock;
      v.hash = hash_at(i);
      want.push_back(v);
      expect[hash_hex(v.hash)] = i;
    }
    try {
      peer->send_message("getdata", encode_getdata(want));
    } catch (const std::exception& e) {
      log_error(e.what(), "rescan");
      if (!rotate_peer(true)) throw;
      refresh_peer_mode(use_bloom);
      continue;  // retry same height batch
    }

    size_t got_blocks = 0;
    auto batch_start = std::chrono::steady_clock::now();
    bool rotated = false;
    while (got_blocks < want.size()) {
      if (stop && stop->load()) return cursor;
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - batch_start)
                        .count();
      if (elapsed > 90000) {
        log_error("rescan batch timeout at height " + std::to_string(h), "rescan");
        break;
      }
      peer = active_peer();
      if (!peer) break;
      try {
        NetMessage msg = peer->receive_message(5000);
        handle_ping(*peer, msg);
        if (msg.command == "notfound") {
          // Do not advance the scan cursor over missing blocks.
          log_error("rescan notfound; rotating", "rescan");
          if (!rotate_peer(true)) throw std::runtime_error("no peers available");
          refresh_peer_mode(use_bloom);
          rotated = true;
          break;
        }
        if (msg.command == "merkleblock" && use_bloom) {
          MerkleBlockMatch mb = parse_merkleblock(msg.payload);
          Hash256 bh = mb.header.hash();
          std::string key = hash_hex(bh);
          auto it = expect.find(key);
          if (it == expect.end()) continue;  // unexpected; wait for requested heights
          uint32_t height = it->second;
          ++got_blocks;
          for (const auto& txid : mb.matched_txids) {
            std::string tkey = hash_hex(txid);
            pending_txids_.insert(tkey);
            txid_height_[tkey] = height;
            txid_block_[tkey] = bh;
          }
          if (height > cursor) cursor = height;
          if (on_progress) on_progress(height, tip_hash_);
          continue;
        }
        if (msg.command == "block") {
          const uint8_t* p = msg.payload.data();
          const uint8_t* pend = msg.payload.data() + msg.payload.size();
          if (static_cast<size_t>(pend - p) < 80) continue;
          BlockHeader hdr = BlockHeader::deserialize(p, pend);
          p += 80;
          Hash256 bh = hdr.hash();
          std::string key = hash_hex(bh);
          auto it = expect.find(key);
          if (it == expect.end()) continue;
          uint32_t height = it->second;
          ++got_blocks;
          uint64_t ntx = read_varint(p, pend);
          for (uint64_t i = 0; i < ntx; ++i) {
            Transaction tx = deserialize_tx_at(p, pend);
            bool match = false;
            for (const auto& out : tx.vout) {
              if (bloom_.contains(out.script_pubkey)) {
                match = true;
                break;
              }
            }
            if (!match) {
              for (const auto& in : tx.vin) {
                Bytes op;
                append_bytes(op, in.prev.txid.data(), 32);
                append_u32le(op, in.prev.vout);
                if (bloom_.contains(op)) {
                  match = true;
                  break;
                }
              }
            }
            if (match && on_tx) on_tx(tx, height, bh);
          }
          if (height > cursor) cursor = height;
          if (on_progress) on_progress(height, tip_hash_);
          continue;
        }
        ProgressFn prog = on_progress;
        handle_filter_message(*peer, msg, on_tx, prog);
      } catch (const std::runtime_error& e) {
        std::string what = e.what();
        if (what.find("receive timeout") != std::string::npos) continue;
        if (is_hard_peer_error(what)) {
          log_error(what, "rescan");
          if (!rotate_peer(true)) throw;
          refresh_peer_mode(use_bloom);
          rotated = true;
          break;  // retry same batch on new peer
        }
      }
    }

    if (rotated) continue;

    if (got_blocks < want.size()) {
      // Incomplete batch (timeout) — rotate and retry the same heights; never skip.
      log_error("rescan incomplete at height " + std::to_string(h) + "; retry", "rescan");
      if (!rotate_peer(true)) throw std::runtime_error("no peers available");
      refresh_peer_mode(use_bloom);
      continue;
    }

    for (int i = 0; i < 30 && !pending_txids_.empty(); ++i) {
      if (stop && stop->load()) break;
      peer = active_peer();
      if (!peer) break;
      try {
        NetMessage msg = peer->receive_message(500);
        handle_ping(*peer, msg);
        ProgressFn prog = on_progress;
        handle_filter_message(*peer, msg, on_tx, prog);
      } catch (...) {
        break;
      }
    }

    h = end + 1;
  }
  return cursor;
}

void SpvNode::disconnect_peers() {
  peers_.clear();
  active_idx_ = 0;
}

void SpvNode::poll_network(TxHandler on_tx, ProgressFn on_progress, int duration_ms,
                           std::atomic<bool>* stop) {
  ensure_peer();
  if (!bloom_set_) throw std::runtime_error("bloom filter not set");
  Peer* peer = active_peer();
  if (!peer) throw std::runtime_error("no peers available");
  if (!peer->peer_supports_bloom()) {
    if (!rotate_peer(true)) throw std::runtime_error("no bloom peers available");
    peer = active_peer();
    if (!peer || !peer->peer_supports_bloom())
      throw std::runtime_error("no bloom peers available");
  }
  send_filterload();
  request_filtered_blocks(*peer);
  request_headers(*peer);

  auto start = std::chrono::steady_clock::now();
  auto last_headers_req = start;
  auto last_blocks_req = start;
  while (true) {
    if (stop && stop->load()) break;
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() >= duration_ms)
      break;

    peer = active_peer();
    if (!peer) {
      if (!rotate_peer(true)) throw std::runtime_error("no peers available");
      peer = active_peer();
      send_filterload();
      request_filtered_blocks(*peer);
      request_headers(*peer);
      continue;
    }

    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_headers_req).count() >= 30) {
      try {
        request_headers(*peer);
      } catch (const std::exception& e) {
        log_error(e.what(), "poll_network");
        if (!rotate_peer(true)) throw;
        peer = active_peer();
        if (peer) {
          request_filtered_blocks(*peer);
          request_headers(*peer);
        }
      }
      last_headers_req = now;
    }
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_blocks_req).count() >= 60) {
      try {
        request_filtered_blocks(*peer);
      } catch (const std::exception& e) {
        log_error(e.what(), "poll_network");
        if (!rotate_peer(true)) throw;
        peer = active_peer();
        if (peer) {
          request_filtered_blocks(*peer);
          request_headers(*peer);
        }
      }
      last_blocks_req = now;
    }

    NetMessage msg;
    try {
      msg = peer->receive_message(1000);
    } catch (const std::runtime_error& e) {
      std::string what = e.what();
      if (what.find("receive timeout") == std::string::npos) {
        log_error(what, "poll_network");
        if (is_hard_peer_error(what)) {
          if (!rotate_peer(true)) throw;
          peer = active_peer();
          if (!peer) throw;
          try {
            request_filtered_blocks(*peer);
            request_headers(*peer);
          } catch (const std::exception& re) {
            log_error(re.what(), "poll_network");
          }
          continue;
        }
      }
      try {
        peer->ping();
      } catch (const std::exception& pe) {
        log_error(pe.what(), "poll_network/ping");
        if (is_hard_peer_error(pe.what())) {
          if (!rotate_peer(true)) throw;
          peer = active_peer();
          if (peer) {
            try {
              request_filtered_blocks(*peer);
              request_headers(*peer);
            } catch (...) {
            }
          }
        }
      } catch (...) {
        log_error("ping failed", "poll_network/ping");
      }
      continue;
    }
    handle_ping(*peer, msg);
    handle_filter_message(*peer, msg, on_tx, on_progress);
  }
}

void SpvNode::sync_filtered(TxHandler on_tx, ProgressFn on_progress, int idle_timeout_ms) {
  std::atomic<bool> never{false};
  // Keep polling until idle window with no matched activity is approximated by duration.
  poll_network(std::move(on_tx), std::move(on_progress), idle_timeout_ms, &never);
}

void SpvNode::broadcast_tx(const Transaction& tx) {
  ensure_peer();
  if (peers_.empty()) throw std::runtime_error("no peers available");
  Bytes raw = tx.serialize(true);
  Hash256 id = tx.txid();
  InvVector inv{InvType::WitnessTx, id};
  Bytes inv_payload = encode_inv({inv});

  int ok = 0;
  for (size_t i = 0; i < peers_.size(); ++i) {
    Peer* peer = peers_[i].get();
    if (!peer) continue;
    try {
      peer->send_message("inv", inv_payload);
      peer->send_message("tx", raw);
      ++ok;
    } catch (const std::exception& e) {
      log_error(peer->peer_user_agent() + ": " + e.what(), "broadcast_tx");
    } catch (...) {
      log_error("send failed on peer", "broadcast_tx");
    }
  }
  if (ok == 0) throw std::runtime_error("broadcast failed on all peers");
}

}  // namespace net
}  // namespace ltc

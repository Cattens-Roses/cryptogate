#pragma once
#include "ltc/net/bloom.hpp"
#include "ltc/net/peer.hpp"
#include "ltc/net/serialize.hpp"
#include "ltc/wallet/transaction.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ltc {
namespace net {

struct MerkleBlockMatch {
  BlockHeader header;
  std::vector<Hash256> matched_txids;
};

// Extract matched txids from a BIP37 merkleblock payload (partial merkle tree).
MerkleBlockMatch parse_merkleblock(const Bytes& payload);

class SpvNode {
 public:
  using ProgressFn = std::function<void(uint32_t height, const Hash256& tip)>;
  using TxHandler = std::function<void(const Transaction& tx, uint32_t height, const Hash256& block)>;

  explicit SpvNode(std::string data_dir);
  ~SpvNode();

  // Discover peers via params::kDnsSeeds and connect to at least one.
  // prefer_bloom: try to find a NODE_BLOOM peer (needed for BIP37 filterload).
  bool connect_peers(size_t min_peers = 1, size_t max_peers = 3, bool prefer_bloom = true);

  // Active peer in the pool (may differ from peers_.front() after rotation).
  Peer* active_peer();
  Peer* primary_peer();  // alias of active_peer() for compatibility
  bool has_peer() const;
  size_t peer_count() const { return peers_.size(); }

  // Drop a dead peer; rotate to another pool member (prefer bloom when requested).
  // Re-sends filterload to the new peer when bloom is set. Returns false if no peer left.
  bool drop_peer(Peer* peer);
  bool rotate_peer(bool prefer_bloom = false);
  // Ensure at least min_peers; full DNS rediscovery only when pool is empty.
  bool ensure_peers(size_t min_peers = 1, size_t max_peers = 4, bool prefer_bloom = false);

  void set_bloom(const BloomFilter& filter);
  void send_filterload();
  bool has_bloom() const { return bloom_set_; }

  // Sync headers via getheaders/headers starting from genesis; persist under data_dir/headers.dat
  void sync_headers(ProgressFn on_progress = {});

  // One getheaders round.
  //  1 = more headers likely available
  //  0 = caught up (empty/short batch)
  // -1 = transient (timeout) — retry same peer without treating as done
  // Checks *stop between waits; throws on hard peer failures.
  int sync_headers_round(ProgressFn on_progress = {}, std::atomic<bool>* stop = nullptr);

  // After filterload: getblocks (or process inv) and accept merkleblock + following tx messages.
  // Only matched / filtered transactions are delivered to on_tx.
  void sync_filtered(TxHandler on_tx, ProgressFn on_progress = {}, int idle_timeout_ms = 120000);

  // Rescan known headers [from_height+1 .. tip] with BIP37 merkleblocks.
  // Progress reports the height currently being scanned. Returns last fully scanned height.
  uint32_t rescan_filtered(uint32_t from_height, TxHandler on_tx, ProgressFn on_progress = {},
                           std::atomic<bool>* stop = nullptr);

  // Process P2P traffic for up to duration_ms (or until *stop). Handles inv/merkleblock/tx/headers/ping.
  // Periodically re-requests headers and filtered blocks while watching.
  void poll_network(TxHandler on_tx, ProgressFn on_progress, int duration_ms,
                    std::atomic<bool>* stop = nullptr);

  void disconnect_peers();

  // Broadcast a transaction (inv+getdata reply path, or direct tx message).
  void broadcast_tx(const Transaction& tx);

  uint32_t tip_height() const { return tip_height_; }
  Hash256 tip_hash() const { return tip_hash_; }

  // Hash at height (0=genesis). Reads headers.dat / pending; O(1) for recent tip window.
  Hash256 hash_at(uint32_t height) const;

  // Build locator from stored chain (exponential steps).
  std::vector<Hash256> build_locator() const;

  void load_headers();
  void save_headers() const;
  void flush_headers();  // append any unsaved headers

 private:
  struct PendingHeader {
    BlockHeader header;
    Hash256 hash{};
  };

  void ensure_peer();
  void select_active(bool prefer_bloom);
  static bool is_hard_peer_error(const std::string& what);
  void handle_ping(Peer& peer, const NetMessage& msg);
  // Returns: 1 = more headers likely, 0 = caught up / short batch, -1 = non-connecting batch.
  int process_headers_msg(const Bytes& payload, ProgressFn& on_progress);
  void request_headers(Peer& peer);
  void request_filtered_blocks(Peer& peer);
  // Handle one merkleblock/tx/inv message; returns true if a merkleblock was consumed.
  bool handle_filter_message(Peer& peer, const NetMessage& msg, TxHandler& on_tx,
                             ProgressFn& on_progress);

  std::string headers_path() const;
  std::string tip_path() const;
  void write_tip_file() const;
  bool read_tip_file(uint32_t& height, Hash256& tip) const;
  bool read_disk_header(uint32_t height, BlockHeader& out) const;  // height >= 1
  Hash256 hash_at_disk(uint32_t height) const;
  void push_recent(uint32_t height, const Hash256& hash);
  void preload_recent_cache();
  // Height for hash if known in recent/pending/tip; false if unknown.
  bool find_height_for_hash(const Hash256& bh, uint32_t& height_out) const;

  std::string data_dir_;
  std::vector<std::unique_ptr<Peer>> peers_;
  size_t active_idx_ = 0;
  BloomFilter bloom_;
  bool bloom_set_ = false;

  // Disk-backed chain: headers.dat holds heights 1..disk_height_ (80 bytes each).
  // pending_ holds disk_height_+1 .. tip_height_ not yet flushed.
  uint32_t disk_height_ = 0;
  uint32_t tip_height_ = 0;
  Hash256 tip_hash_{};
  std::vector<PendingHeader> pending_;
  mutable size_t headers_since_flush_ = 0;
  uint32_t last_progress_height_ = 0;

  // Hot window around tip for locator / merkle height lookup (avoids disk).
  static constexpr uint32_t kRecentWindow = 8192;
  std::vector<Hash256> recent_hashes_;  // size <= kRecentWindow; covers [tip-n+1 .. tip]
  uint32_t recent_base_ = 0;            // height of recent_hashes_[0]

  std::unordered_set<std::string> pending_txids_;  // hex internal order
  std::unordered_map<std::string, uint32_t> txid_height_;
  std::unordered_map<std::string, Hash256> txid_block_;
};

}  // namespace net
}  // namespace ltc

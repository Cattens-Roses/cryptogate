#pragma once
#include "ltc/net/spv.hpp"
#include "ltc/wallet/wallet.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace ltc {

struct SyncStatus {
  enum class Phase {
    Stopped,
    Connecting,
    SyncingHeaders,
    Watching,
    Paused,
    Reconnecting,
    Error,
  };

  Phase phase = Phase::Stopped;
  bool running = false;
  bool connected = false;
  uint32_t tip_height = 0;
  uint32_t target_height = 0;  // peer reported height (for x/x)
  std::string tip_hash;        // display hex
  int peers = 0;
  int32_t peer_height = 0;
  std::string peer_agent;
  int64_t balance_sats = 0;
  uint64_t matched_txs = 0;
  double headers_per_sec = 0;  // EMA download rate
  int64_t eta_seconds = -1;    // -1 = unknown
  bool rescanning = false;
  uint32_t rescan_height = 0;  // height currently being bloom-scanned
  std::string detail;
  std::string last_error;
  std::string conn_status;  // connecting | connected | reconnecting | disconnected
};

const char* sync_phase_name(SyncStatus::Phase p);
std::string sync_progress_label(const SyncStatus& st);  // e.g. "downloading blocks 12000/1850000 · eta 4m"
std::string sync_conn_label(const SyncStatus& st);      // connected / connecting / ...
std::string format_eta(int64_t seconds);                // "eta 4m 12s" / "eta …"


// Owns a background thread that continuously syncs headers + filtered txs.
class BackgroundSync {
 public:
  BackgroundSync();
  ~BackgroundSync();

  BackgroundSync(const BackgroundSync&) = delete;
  BackgroundSync& operator=(const BackgroundSync&) = delete;

  // Start continuous sync for wallet (non-owning). Safe to call if already running (no-op).
  void start(Wallet* wallet, const std::string& password);
  void stop();
  void pause();
  void resume();
  bool running() const { return running_.load(); }

  // Ask sync loop to rebuild bloom (e.g. after new address).
  void request_bloom_refresh();

  SyncStatus status() const;

  // Serialize wallet access with the sync thread.
  std::mutex& wallet_mutex() { return wallet_mu_; }

 private:
  void thread_main();
  void set_phase(SyncStatus::Phase p, const std::string& detail = {});
  void update_tip(uint32_t height, const Hash256& tip);
  void reset_rate();
  void refresh_eta_locked();  // caller holds status_mu_
  net::BloomFilter build_bloom_locked();

  mutable std::mutex status_mu_;
  SyncStatus status_{};

  std::mutex wallet_mu_;
  Wallet* wallet_ = nullptr;
  std::string password_;
  std::string data_dir_;

  uint32_t rate_sample_height_ = 0;
  std::chrono::steady_clock::time_point rate_sample_time_{};
  double rate_ema_ = 0;

  std::atomic<bool> stop_{true};
  std::atomic<bool> pause_{false};
  std::atomic<bool> bloom_dirty_{true};
  std::atomic<bool> running_{false};
  std::thread thread_;
};

}  // namespace ltc
